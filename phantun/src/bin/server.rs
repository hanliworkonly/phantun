use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info, warn};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use phantun::{MULTISTREAM_HEADER_LEN, MULTISTREAM_MAGIC, MULTISTREAM_VERSION, UDP_TTL};

/// Information extracted from a multi-stream handshake packet
#[derive(Debug, Clone)]
struct MultiStreamInfo {
    stream_id: Uuid,
    stream_index: u8,
    total_streams: u8,
    user_payload: Option<Vec<u8>>,
}

/// Parse a potential multi-stream handshake packet
/// Returns Some(MultiStreamInfo) if it's a valid multi-stream handshake, None otherwise
fn parse_multistream_handshake(data: &[u8]) -> Option<MultiStreamInfo> {
    if data.len() < MULTISTREAM_HEADER_LEN {
        return None;
    }

    // Check magic number
    if &data[0..4] != MULTISTREAM_MAGIC {
        return None;
    }

    // Check version
    if data[4] != MULTISTREAM_VERSION {
        warn!("Unknown multi-stream protocol version: {}", data[4]);
        return None;
    }

    // Extract stream ID (UUID)
    let stream_id_bytes: [u8; 16] = data[5..21].try_into().ok()?;
    let stream_id = Uuid::from_bytes(stream_id_bytes);

    // Extract stream index and total streams
    let stream_index = data[21];
    let total_streams = data[22];

    // Extract optional user payload
    let user_payload = if data.len() > MULTISTREAM_HEADER_LEN {
        Some(data[MULTISTREAM_HEADER_LEN..].to_vec())
    } else {
        None
    };

    Some(MultiStreamInfo {
        stream_id,
        stream_index,
        total_streams,
        user_payload,
    })
}

/// Manages a group of TCP streams that belong to the same logical connection
struct StreamGroup {
    stream_id: Uuid,
    total_streams: u8,
    sockets: Arc<RwLock<HashMap<u8, Arc<Socket>>>>, // stream_index -> Socket
    received_count: AtomicU8,
    udp_sock: Arc<UdpSocket>,
    packet_received: Arc<Notify>,
    quit: CancellationToken,
}

impl StreamGroup {
    fn new(stream_id: Uuid, total_streams: u8, udp_sock: Arc<UdpSocket>) -> Arc<Self> {
        Arc::new(StreamGroup {
            stream_id,
            total_streams,
            sockets: Arc::new(RwLock::new(HashMap::new())),
            received_count: AtomicU8::new(0),
            udp_sock,
            packet_received: Arc::new(Notify::new()),
            quit: CancellationToken::new(),
        })
    }

    async fn add_socket(&self, stream_index: u8, socket: Arc<Socket>) -> bool {
        let mut sockets = self.sockets.write().await;
        if sockets.contains_key(&stream_index) {
            warn!("Stream index {} already exists in group {}", stream_index, self.stream_id);
            return false;
        }

        sockets.insert(stream_index, socket);
        let count = self.received_count.fetch_add(1, Ordering::SeqCst) + 1;

        info!("Stream {}/{} added to group {}", count, self.total_streams, self.stream_id);

        count == self.total_streams
    }

    async fn get_all_sockets(&self) -> Vec<Arc<Socket>> {
        self.sockets.read().await.values().cloned().collect()
    }
}

/// Spawn worker tasks for a complete stream group
fn spawn_stream_group_workers(
    group: Arc<StreamGroup>,
    remote_addr: SocketAddr,
    num_cpus: usize,
    stream_groups: Arc<RwLock<HashMap<Uuid, Arc<StreamGroup>>>>,
) {
    let stream_id = group.stream_id;

    // Connect UDP socket to remote
    let udp_sock = group.udp_sock.clone();
    let udp_sock_for_connect = udp_sock.clone();
    tokio::spawn(async move {
        udp_sock_for_connect.connect(remote_addr).await.unwrap();
        info!("Stream group {} UDP socket connected to {}", stream_id, remote_addr);
    });

    // Spawn TCP->UDP workers for each stream
    tokio::spawn(async move {
        let sockets = group.get_all_sockets().await;

        for (stream_idx, sock) in sockets.iter().enumerate() {
            for worker_id in 0..num_cpus {
                let sock = sock.clone();
                let udp_sock = udp_sock.clone();
                let quit = group.quit.clone();
                let packet_received = group.packet_received.clone();

                tokio::spawn(async move {
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];

                    loop {
                        tokio::select! {
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                error!("Unable to send UDP packet to {}: {}, closing connection", remote_addr, e);
                                                quit.cancel();
                                                return;
                                            }
                                        }
                                    },
                                    None => {
                                        debug!("TCP stream {} in group closed", stream_idx);
                                        quit.cancel();
                                        return;
                                    },
                                }
                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("TCP->UDP worker {} for stream {} terminated", worker_id, stream_idx);
                                return;
                            },
                        }
                    }
                });
            }
        }

        // Spawn UDP->TCP workers (distribute across all TCP streams)
        for worker_id in 0..num_cpus {
            let sockets = group.get_all_sockets().await;
            let udp_sock = udp_sock.clone();
            let quit = group.quit.clone();
            let packet_received = group.packet_received.clone();
            let socket_count = sockets.len();

            tokio::spawn(async move {
                let mut buf_udp = [0u8; MAX_PACKET_LEN];
                let mut next_socket_idx = 0usize;

                loop {
                    tokio::select! {
                        Ok(size) = udp_sock.recv(&mut buf_udp) => {
                            // Round-robin distribution across TCP streams
                            let sock = &sockets[next_socket_idx % socket_count];
                            next_socket_idx = next_socket_idx.wrapping_add(1);

                            if sock.send(&buf_udp[..size]).await.is_none() {
                                error!("Failed to send to TCP stream, closing connection");
                                quit.cancel();
                                return;
                            }

                            packet_received.notify_one();
                        },
                        _ = quit.cancelled() => {
                            debug!("UDP->TCP worker {} terminated", worker_id);
                            return;
                        },
                    }
                }
            });
        }

        // Spawn timeout monitor
        let quit = group.quit.clone();
        let packet_received = group.packet_received.clone();
        tokio::spawn(async move {
            loop {
                let read_timeout = time::sleep(UDP_TTL);
                let packet_received_fut = packet_received.notified();

                tokio::select! {
                    _ = read_timeout => {
                        info!("No traffic seen in the last {:?} for group {}, closing connection", UDP_TTL, stream_id);
                        stream_groups.write().await.remove(&stream_id);
                        quit.cancel();
                        return;
                    },
                    _ = packet_received_fut => {},
                }
            }
        });
    });
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
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

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    // Track stream groups by stream_id
    let stream_groups: Arc<RwLock<HashMap<Uuid, Arc<StreamGroup>>>> = Arc::new(RwLock::new(HashMap::new()));

    let main_loop = tokio::spawn(async move {
        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        loop {
            let sock = Arc::new(stack.accept().await);
            info!("New connection: {}", sock);

            // Try to read the first packet to check if it's a multi-stream handshake
            let first_packet = tokio::select! {
                res = sock.recv(&mut buf_tcp) => {
                    match res {
                        Some(size) if size > 0 => Some(buf_tcp[..size].to_vec()),
                        _ => None,
                    }
                }
                _ = time::sleep(time::Duration::from_secs(5)) => {
                    warn!("Timeout waiting for first packet from {}", sock);
                    None
                }
            };

            if first_packet.is_none() {
                error!("No first packet received from {}, closing connection", sock);
                continue;
            }

            let first_packet = first_packet.unwrap();

            // Try to parse as multi-stream handshake
            let ms_info = parse_multistream_handshake(&first_packet);

            if let Some(info) = ms_info {
                // This is a multi-stream connection
                info!("Multi-stream connection detected: stream {}/{} of group {}",
                      info.stream_index + 1, info.total_streams, info.stream_id);

                // Send user handshake response if provided
                if let Some(ref _user_payload) = info.user_payload {
                    if let Some(ref response) = handshake_packet {
                        if sock.send(response).await.is_none() {
                            error!("Failed to send handshake response, closing connection");
                            continue;
                        }
                        debug!("Sent handshake response to stream {}", info.stream_index);
                    }
                } else if let Some(ref p) = handshake_packet {
                    if sock.send(p).await.is_none() {
                        error!("Failed to send handshake packet to remote, closing connection.");
                        continue;
                    }
                    debug!("Sent handshake packet to: {}", sock);
                }

                // Get or create stream group
                let group = {
                    let mut groups = stream_groups.write().await;
                    if !groups.contains_key(&info.stream_id) {
                        // Create UDP socket for this new stream group
                        let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        }).await.unwrap();
                        let udp_sock = Arc::new(udp_sock);

                        info!("Created stream group {} with {} total streams",
                              info.stream_id, info.total_streams);

                        let new_group = StreamGroup::new(info.stream_id, info.total_streams, udp_sock);
                        groups.insert(info.stream_id, new_group);
                    }
                    groups.get(&info.stream_id).unwrap().clone()
                };

                // Add this socket to the group
                let is_complete = group.add_socket(info.stream_index, sock.clone()).await;

                if is_complete {
                    // All streams for this group have connected
                    info!("Stream group {} is now complete, starting workers", info.stream_id);

                    // Spawn workers for this stream group
                    spawn_stream_group_workers(
                        group.clone(),
                        remote_addr,
                        num_cpus,
                        stream_groups.clone(),
                    );
                } else {
                    info!("Waiting for more streams in group {} ({}/{})",
                          info.stream_id,
                          group.received_count.load(Ordering::SeqCst),
                          group.total_streams);
                }
            } else {
                // This is a legacy single-stream connection
                info!("Legacy single-stream connection from {}", sock);

                // For legacy connections, forward the first packet to UDP
                let first_packet_data = first_packet.clone();

                let packet_received = Arc::new(Notify::new());
                let quit = CancellationToken::new();
                let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .await?;
                let local_addr = udp_sock.local_addr()?;
                drop(udp_sock);

                for i in 0..num_cpus {
                    let sock = sock.clone();
                    let quit = quit.clone();
                    let packet_received = packet_received.clone();
                    let udp_sock = new_udp_reuseport(local_addr);
                    let first_pkt = if i == 0 { Some(first_packet_data.clone()) } else { None };

                    tokio::spawn(async move {
                        let mut buf_udp = [0u8; MAX_PACKET_LEN];
                        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

                        udp_sock.connect(remote_addr).await.unwrap();

                        // Send first packet if this is worker 0
                        if let Some(pkt) = first_pkt {
                            if let Err(e) = udp_sock.send(&pkt).await {
                                error!("Failed to forward first packet to UDP: {}", e);
                                quit.cancel();
                                return;
                            }
                        }

                        loop {
                            tokio::select! {
                                Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                    if sock.send(&buf_udp[..size]).await.is_none() {
                                        quit.cancel();
                                        return;
                                    }

                                    packet_received.notify_one();
                                },
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
                                            quit.cancel();
                                            return;
                                        },
                                    }

                                    packet_received.notify_one();
                                },
                                _ = quit.cancelled() => {
                                    debug!("worker {} terminated", i);
                                    return;
                                },
                            };
                        }
                    });
                }

                tokio::spawn(async move {
                    loop {
                        let read_timeout = time::sleep(UDP_TTL);
                        let packet_received_fut = packet_received.notified();

                        tokio::select! {
                            _ = read_timeout => {
                                info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);

                                quit.cancel();
                                return;
                            },
                            _ = packet_received_fut => {},
                        }
                    }
                });
            }
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
