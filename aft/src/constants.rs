/// Maximum filetype length.
pub const MAX_TYPE_LEN: usize = 20;
/// Maximum name length.
// 50 is an optimal name length.
pub const MAX_FILENAME_LEN: usize = 50;
/// Maximum length of "size" in JSON `metadata`.
// 20 = len(u64::Max)
pub const MAX_SIZE_LEN: usize = 20;
/// Maximum length of the "modified" in the `metadata` JSON.
pub const MAX_MODIFIED_LEN: usize = 12;
/// Maximum username length.
pub const MAX_IDENTIFIER_LEN: usize = 10;
/// Maximum buffer length that is received from a stream.
pub const MAX_METADATA_LEN: usize = MAX_FILENAME_LEN + MAX_TYPE_LEN + MAX_SIZE_LEN + MAX_MODIFIED_LEN + 40 /* 40 = other chars such as { */;
/// Maximum size of a chunk (64KB).
pub const MAX_CONTENT_LEN: usize = 65536;
/// Maximum checksum length (Sha256 length in bytes).
pub const MAX_CHECKSUM_LEN: usize = 32;
/// Length of a blocks column.
pub const MAX_BLOCKS_LEN: usize = 3000;
/// Code for a client that sends data.
pub const CLIENT_SEND: u8 = 0;
/// Code for a client that receives data.
pub const CLIENT_RECV: u8 = 1;
/// Code for a relay, acting as a proxy.
pub const RELAY: u8 = 2;
/// Signal length.
pub const SIGNAL_LEN: usize = 6;
/// SHA-256 hash length in bytes.
pub const SHA_256_LEN: usize = 32;
/// Blocked user filename.
pub const BLOCKED_FILENAME: &str = ".blocks";
/// aft directory name.
pub const AFT_DIRNAME: &str = ".aft";
