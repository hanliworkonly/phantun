use std::time::Duration;

pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);

// Multi-stream protocol constants
pub const MULTISTREAM_MAGIC: &[u8; 4] = b"PMTS"; // Phantun Multi-Stream
pub const MULTISTREAM_VERSION: u8 = 1;
pub const MULTISTREAM_HEADER_LEN: usize = 4 + 1 + 16 + 1 + 1; // magic + version + uuid + index + total = 23 bytes
