use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport, udp_recv_pktinfo};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use phantun::{MULTISTREAM_HEADER_LEN, MULTISTREAM_MAGIC, MULTISTREAM_VERSION, UDP_TTL};

/// Build a multi-stream handshake packet
/// Format: [MAGIC(4)][VERSION(1)][STREAM_ID(16)][STREAM_INDEX(1)][TOTAL_STREAMS(1)][USER_PACKET]
fn build_multistream_handshake(
    stream_id: &Uuid,
    stream_index: u8,
    total_streams: u8,
    user_handshake: Option<&[u8]>,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MULTISTREAM_HEADER_LEN + user_handshake.map_or(0, |p| p.len()));

    // Magic number
    packet.extend_from_slice(MULTISTREAM_MAGIC);

    // Version
    packet.push(MULTISTREAM_VERSION);

    // Stream ID (UUID as bytes)
    packet.extend_from_slice(stream_id.as_bytes());

    // Stream index
    packet.push(stream_index);

    // Total streams
    packet.push(total_streams);

    // Append user's custom handshake packet if provided
    if let Some(user_pkt) = user_handshake {
        packet.extend_from_slice(user_pkt);
    }

    packet
}

/// Manages multiple TCP streams for a single UDP connection
///
/// This struct enables load balancing of UDP packets across multiple TCP connections,
/// which can improve throughput on multi-core systems by parallelizing the TCP processing.
///
/// ## Implementation:
/// - Each UDP connection can use N parallel TCP streams (configured via --streams)
/// - Client generates a unique stream-id (UUID) for each multi-stream connection
/// - Stream-id is transmitted in handshake packets to identify related streams
/// - Server automatically groups streams by stream-id
/// - All streams in a group share a single UDP socket on the server side
/// - Remote UDP server sees packets from a single, consistent source IP:port
/// - Compatible with all UDP protocols, including WireGuard
///
/// ## Protocol:
/// Multi-stream handshake packet format:
/// [MAGIC(4)][VERSION(1)][STREAM_ID(16)][STREAM_INDEX(1)][TOTAL_STREAMS(1)][USER_PACKET...]
/// - MAGIC: "PMTS" (Phantun Multi-Stream)
/// - VERSION: Protocol version (currently 1)
/// - STREAM_ID: UUID identifying the stream group
/// - STREAM_INDEX: Index of this stream (0-based)
/// - TOTAL_STREAMS: Total number of streams in the group
struct MultiStream {
    sockets: Vec<Arc<Socket>>,
    next_socket: AtomicUsize,
}

impl MultiStream {
    fn new(sockets: Vec<Arc<Socket>>) -> Arc<Self> {
        Arc::new(MultiStream {
            sockets,
            next_socket: AtomicUsize::new(0),
        })
    }

    /// Get the next socket using round-robin distribution
    fn get_next_socket(&self) -> &Arc<Socket> {
        let index = self.next_socket.fetch_add(1, Ordering::Relaxed) % self.sockets.len();
        &self.sockets[index]
    }

    /// Get all sockets
    fn get_all_sockets(&self) -> &[Arc<Socket>] {
        &self.sockets
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("streams")
                .long("streams")
                .required(false)
                .value_name("N")
                .help("Number of TCP streams to use for load balancing each UDP connection (default: 1). \
                      Using multiple streams can improve throughput on multi-core systems.")
                .default_value("1")
        )
        .get_matches();

    let local_addr: SocketAddr = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local address");

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;

    let num_streams: usize = matches
        .get_one::<String>("streams")
        .unwrap()
        .parse()
        .expect("streams must be a positive integer");

    if num_streams == 0 {
        panic!("streams must be at least 1");
    }

    if num_streams > 1 {
        info!("Multi-stream mode enabled: {} TCP streams per UDP connection", num_streams);
        info!("Note: Remote UDP server will see packets from {} different source ports", num_streams);
    }

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .unwrap();

    if remote_addr.is_ipv6() {
        assign_ipv6_address(tun[0].name(), tun_local6.unwrap(), tun_peer6.unwrap());
    }

    info!("Created TUN device {}", tun[0].name());

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<MultiStream>>::new()));

    let mut stack = Stack::new(tun, tun_peer, tun_peer6);

    let main_loop = tokio::spawn(async move {
        let mut buf_r = [0u8; MAX_PACKET_LEN];

        loop {
            let (size, udp_remote_addr, udp_local_addr) = udp_recv_pktinfo(&udp_sock, &mut buf_r).await?;
            // seen UDP packet to listening socket, this means:
            // 1. It is a new UDP connection, or
            // 2. It is some extra packets not filtered by more specific
            //    connected UDP socket yet
            if let Some(multi_stream) = connections.read().await.get(&udp_remote_addr) {
                multi_stream.get_next_socket().send(&buf_r[..size]).await;
                continue;
            }

            info!("New UDP client from {}", udp_remote_addr);

            // Generate stream ID for multi-stream connections
            let stream_id = if num_streams > 1 {
                Some(Uuid::new_v4())
            } else {
                None
            };

            if let Some(ref sid) = stream_id {
                info!("Generated stream ID {} for multi-stream connection", sid);
            }

            // Create multiple TCP connections for load balancing
            let mut sockets = Vec::with_capacity(num_streams);
            for i in 0..num_streams {
                let sock = stack.connect(remote_addr).await;
                if sock.is_none() {
                    error!("Unable to connect to remote {} (stream {}/{})", remote_addr, i + 1, num_streams);
                    // Clean up any sockets we already created
                    break;
                }

                let sock = Arc::new(sock.unwrap());

                // Send handshake packet
                // For multi-stream: send stream-id header + optional user packet
                // For single-stream: send user packet only (backward compatible)
                let handshake_to_send = if let Some(ref sid) = stream_id {
                    // Multi-stream mode: build protocol header
                    build_multistream_handshake(
                        sid,
                        i as u8,
                        num_streams as u8,
                        handshake_packet.as_deref(),
                    )
                } else if let Some(ref p) = handshake_packet {
                    // Single-stream mode with user packet
                    p.clone()
                } else {
                    // No handshake packet needed
                    Vec::new()
                };

                if !handshake_to_send.is_empty() {
                    if sock.send(&handshake_to_send).await.is_none() {
                        error!("Failed to send handshake packet to remote on stream {}/{}, closing connection.", i + 1, num_streams);
                        break;
                    }
                    if stream_id.is_some() {
                        debug!("Sent multi-stream handshake to: {} (stream {}/{}, ID: {})",
                               sock, i + 1, num_streams, stream_id.unwrap());
                    } else {
                        debug!("Sent handshake packet to: {}", sock);
                    }
                }

                sockets.push(sock);
            }

            // Check if all connections were successful
            if sockets.len() != num_streams {
                error!("Failed to create all {} streams, only {} succeeded. Skipping this connection.", num_streams, sockets.len());
                continue;
            }

            info!("Created {} TCP streams for UDP client {}", num_streams, udp_remote_addr);

            // Send first packet on first stream (round-robin will start from stream 0)
            if sockets[0].send(&buf_r[..size]).await.is_none() {
                continue;
            }

            let multi_stream = MultiStream::new(sockets);
            assert!(connections
                .write()
                .await
                .insert(udp_remote_addr, multi_stream.clone())
                .is_none());
            debug!("inserted {} fake TCP sockets into connection table", num_streams);

            // spawn "fastpath" UDP socket and task, this will offload main task
            // from forwarding UDP packets

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();

            // Create shared UDP socket for this connection
            let bind_addr = match (udp_remote_addr, udp_local_addr) {
                (SocketAddr::V4(_), IpAddr::V4(udp_local_ipv4)) => {
                    SocketAddr::V4(SocketAddrV4::new(
                        udp_local_ipv4,
                        local_addr.port(),
                    ))
                }
                (SocketAddr::V6(udp_remote_addr), IpAddr::V6(udp_local_ipv6)) => {
                    SocketAddr::V6(SocketAddrV6::new(
                        udp_local_ipv6,
                        local_addr.port(),
                        udp_remote_addr.flowinfo(),
                        udp_remote_addr.scope_id(),
                    ))
                }
                (_, _) => {
                    panic!("unexpected family combination for udp_remote_addr={udp_remote_addr} and udp_local_addr={udp_local_addr}");
                }
            };
            let shared_udp_sock = Arc::new(new_udp_reuseport(bind_addr));
            shared_udp_sock.connect(udp_remote_addr).await.unwrap();

            // Spawn workers for UDP -> TCP (using round-robin across streams)
            for i in 0..num_cpus {
                let multi_stream = multi_stream.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let udp_sock = shared_udp_sock.clone();

                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                // Distribute packets across TCP streams using round-robin
                                if multi_stream.get_next_socket().send(&buf_udp[..size]).await.is_none() {
                                    debug!("failed to send to TCP stream, closing connection");
                                    quit.cancel();
                                    return;
                                }
                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("UDP->TCP worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            // Spawn workers for each TCP stream to handle TCP -> UDP
            for (stream_idx, sock) in multi_stream.get_all_sockets().iter().enumerate() {
                for i in 0..num_cpus {
                    let sock = sock.clone();
                    let quit = quit.clone();
                    let packet_received = packet_received.clone();
                    let udp_sock = shared_udp_sock.clone();

                    tokio::spawn(async move {
                        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

                        loop {
                            tokio::select! {
                                res = sock.recv(&mut buf_tcp) => {
                                    match res {
                                        Some(size) => {
                                            if size > 0
                                                && let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                    error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                    quit.cancel();
                                                    return;
                                                }
                                        },
                                        None => {
                                            debug!("TCP stream {} closed", stream_idx);
                                            quit.cancel();
                                            return;
                                        },
                                    }
                                    packet_received.notify_one();
                                },
                                _ = quit.cancelled() => {
                                    debug!("TCP->UDP worker {} for stream {} terminated", i, stream_idx);
                                    return;
                                },
                            };
                        }
                    });
                }
            }

            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);
                            connections.write().await.remove(&udp_remote_addr);
                            debug!("removed fake TCP socket from connections table");

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => {
                            connections.write().await.remove(&udp_remote_addr);
                            debug!("removed fake TCP socket from connections table");
                            return;
                        },
                        _ = packet_received_fut => {},
                    }
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
