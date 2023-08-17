// TODO: Convert these types to u8 or u16.
/// Maximum filetype length.
pub const MAX_TYPE_LEN: usize = 20;
/// Maximum name length.
// 50 is an optimal name length.
pub const MAX_NAME_LEN: usize = 50;
/// Maximum length of "size" in JSON `metadata`.
// 20 = len(u64::Max)
pub const MAX_SIZE_LEN: usize = 20;
/// Maximum length of the "modified" in the `metadata` JSON.
pub const MAX_MODIFIED_LEN: usize = 12;
/// Maximum buffer length that is received from a stream.
pub const MAX_METADATA_LEN: usize = MAX_NAME_LEN + MAX_TYPE_LEN + MAX_SIZE_LEN + MAX_MODIFIED_LEN + MAX_IDENTIFIER_LEN + 40 /* 40 = other chars such as { */;
/// Maximum size `info` in JSON chunk.
// 40 = len(u64::Max) * 2
pub const MAX_INFO_LEN: usize = 2048;
/// Maximum size of a chunk.
pub const MAX_CONTENT_LEN: usize = 1024;
/// Maximum chunk length that is received from a stream.
pub const MAX_CHUNK_LEN: usize = MAX_INFO_LEN + MAX_CONTENT_LEN;
/// Maximum username length.
pub const MAX_IDENTIFIER_LEN: usize = 30;
/// Maximum checksum length (Sha256 length in hex).
// pub const MAX_CHECKSUM_LEN: usize = 64;
pub const MAX_CHECKSUM_LEN: usize = 32;
/// Code for a client that sends data.
pub const CLIENT_SEND: u8 = 0;
/// Code for a client that receives data.
pub const CLIENT_RECV: u8 = 1;
/// Code for a server, acting as a proxy.
pub const SERVER: u8 = 2;
/// End signal in ASCII.
pub const END_SIGNAL: u8 = 49;
/// Signal length.
pub const SIGNAL_LEN: usize = 6;
/// TEMPORARY. Password length in bytes.
pub const PASS_LEN: usize = 64;
