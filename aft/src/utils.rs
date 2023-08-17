/// Module for various utilities used in other modules.

use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use tokio::io::AsyncWriteExt;
use std::io;
use std::net::TcpStream;
use log::{info, warn, debug};
use sha2::{Sha256, Digest};
use crate::errors::Errors;

#[derive(Debug, PartialEq, Eq)]
pub enum Signals {
    /// End file transfer.
    EndFt,
    /// Client not online.
    ClientNotOnline,
    /// Register a user on server.
    Register,
    /// Start the transfer.
    StartFt,
    /// Stop the transfer.
    CloseFt,
    /// Login.
    Login,
    /// Ok.
    OK,
    /// Error.
    Error,
    /// Unspecific signal. Custimized by the enviornment.
    Other,
    /// Unknown signal.
    Unknown
}

impl From<&str> for Signals {
    fn from(v: &str) -> Self {
        match v {
            "FTSIG1" => Signals::EndFt,
            "FTSIG2" => Signals::ClientNotOnline,
            "FTSIG3" => Signals::Register,
            "FTSIG4" => Signals::StartFt,
            "FTSIG5" => Signals::CloseFt,
            "FTSIG6" => Signals::Login,
            "FTSIG7" => Signals::OK,
            "FTSIG8" => Signals::Error,
            "FTSIG9" => Signals::Other,
            _ => Signals::Unknown
        }
    }
}

impl From<&Signals> for &str {
    fn from(v: &Signals) -> Self {
        match v {
           Signals::EndFt => "FTSIG1",
           Signals::ClientNotOnline => "FTSIG2",
           Signals::Register => "FTSIG3",
           Signals::StartFt => "FTSIG4",
           Signals::CloseFt => "FTSIG5",
           Signals::Login => "FTSIG6",
           Signals::OK => "FTSIG7",
           Signals::Error => "FTSIG8",
           Signals::Other => "FTSIG9",
           _ => "FTSIG"
        }
    }
}

impl std::fmt::Display for Signals {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Signals::EndFt => write!(f, "End file transfer successfully."),
            Signals::ClientNotOnline => write!(f, "Client is not online."),
            Signals::Register => write!(f, "Register."),
            Signals::StartFt => write!(f, "Start the transfer."),
            Signals::CloseFt => write!(f, "Stop the transfer."),
            Signals::Login => write!(f, "Login."),
            Signals::OK => write!(f, "Ok."),
            Signals::Error => write!(f, "Error."),
            Signals::Other => write!(f, "Other."),
            _ => write!(f, "Unknown signal.")
        }
    }
}

impl Signals {
    pub fn as_str(&self) -> &str {
        self.into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

/// Creates a new IPv4. Returns 127.0.0.1 if $ip is empty or corrupted. Else, returns IpAddr::V4
/// struct with $ip.
macro_rules! new_ip {
    ($ip:expr) => {
        if $ip.len() == 0 || $ip.len() != 4 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        }
        // $ip in this case, needs to be a Vec<usize>.
        else {
            $ip.parse().expect("Wrong IPv4 format.")
        }
    }
} pub(crate) use new_ip;

/// Macro to shorten "other" errors.
macro_rules! error_other {
    ($E:expr) => {std::io::Error::new(io::ErrorKind::Other, $E)}
} pub(crate) use error_other;

/// Represents a client file. Provides special methods that are used in this program.
pub struct FileOperations {
    pub file: File,
    hasher: Sha256
}

impl FileOperations {
    /// New FileOperations object and opens `path`.
    pub fn new(path: &str) -> io::Result<Self> {
        let file = FileOperations::open_w_file(path)?;
        Ok(FileOperations {
            file,
            hasher: Sha256::new()
        })
    }

    /// Create file at `path` and return FileOperations object.
    ///
    /// Error when there is an IO error.
    pub fn new_create(path: &str) -> io::Result<Self> {
        let file = FileOperations::create_file(path)?;
        Ok(FileOperations {
            file,
            hasher: Sha256::new()
        })
    }

    /// Opens a file, given a filename (or a path).
    ///
    /// Error when there is an IO error.
    pub fn open_file(filename: &str) -> io::Result<File> {
        info!("Opening file: {}", filename);
        File::open(filename)
    }

    /// Opens a file in write and read only mode.
    ///
    /// Error when there is an IO error.
    pub fn open_w_file(filename: &str) -> io::Result<File> {
        debug!("Opening file in write mode: {}", filename);
        let file = File::options().write(true).read(true).open(filename)?;
        Ok(file)
    }

    /// Function to create a file, given a filename (or a path).
    ///
    /// Error when there is an IO error.
    pub fn create_file(filename: &str) -> io::Result<File> {
        debug!("Creating/overwriting file: {}", filename);
        let file = File::options().truncate(true).create(true).write(true).read(true).open(filename)?;
        Ok(file)
    }

    /// Reads from the file and moves the file cursor.
    ///
    /// Returns the position of the file after reading.
    pub fn read_seek_file_sized(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.file.read(buffer)?;
        Ok(bytes_read)
    }

    pub fn write(&mut self, buffer: &[u8]) -> io::Result<()> {
        if !buffer.is_empty() {
            self.file.write_all(buffer)?;
        }
        Ok(())
    }

    pub fn seek_start(&mut self, pos: u64) -> io::Result<u64> {
        self.file.seek(SeekFrom::Start(pos))
    }

    pub fn seek_end(&mut self, pos: i64) -> io::Result<u64> {
        self.file.seek(SeekFrom::End(pos))
    }

    /// Returns the current cursor position in file.
    pub fn get_index(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn is_file_exists(path: &str) -> bool {
        std::path::Path::new(path).is_file()
    }

    pub fn checksum(&self) -> Vec<u8> {
        self.hasher.clone().finalize().to_vec()
    }

    pub fn update_checksum(&mut self, buffer: &[u8]) {
        self.hasher.update(&buffer);
    }

    pub fn reset_checksum(&mut self) {
        self.hasher.reset();
    }
}

/// Writes data to buffer. It firsts sends to the endpoint the size of incoming data, then writes
/// the data itself.
///
/// Returns when an error occurs with the connection.
pub fn write_sized_buffer(socket: &mut (impl Write + Read), buffer: &[u8]) -> Result<(), io::Error> {
    let len_bytes = usize::to_le_bytes(buffer.len());
    // Writing the length of `buffer`, so the other end knows how much to allocate.
    socket.write(&len_bytes)?;
    socket.write_all(buffer)?;
    Ok(())
}

/// Like `write_sized_buffer` but async.
///
/// Returns when an error occurs with the connection.
pub async fn write_sized_buffer_async(socket: &mut (impl AsyncWriteExt + std::marker::Unpin), buffer: &[u8]) -> Result<(), io::Error> {
    let len_bytes = usize::to_le_bytes(buffer.len());
    // write the size of the upcoming buffer
    socket.write(&len_bytes).await?;
    // write buffer
    socket.write_all(buffer).await?;
    Ok(())
}

pub fn read_sized_buffer(socket: &mut TcpStream, size: usize) -> io::Result<Vec::<u8>> {
    // u64, because std::fs::metadata().len() returns u64
    let mut data_len = [0u8; 8];
    socket.read(&mut data_len)?;
    let data_len = usize::from_le_bytes(data_len);
    println!("max size: {size}. actual size: {data_len}");
    if data_len > size {
        // TODO: send error to socket.
        return Err(error_other!(Errors::BufferTooBig))
    }

    let mut data = vec![0u8; data_len];
    let read_size = socket.read(&mut data)?;
    data.truncate(read_size);

    Ok(data)
}

/// Transforms bytes slice to a string (&str).
pub fn bytes_to_string(buffer: &[u8]) -> String {
    String::from_utf8_lossy(buffer).to_string()
}

pub fn progress_bar(pos: u8, max: u8) {
    io::stdout().flush().unwrap();
    if pos == max {
        // clear screen
        print!("\r\n");
    } else {
        print!("\r[{}>{}] {}%", "=".repeat(pos as usize), " ".repeat((max-1 - pos) as usize), pos*2+2);
    }
}

/// Checks JSON format primitively. Meaning it doesn't recurse values, only top ones.
///
/// Returns true when the format is OK, else false.
pub fn check_json(js: &json::JsonValue, keys: &[&str]) -> bool {
    if js.is_empty() {
        return false;
    }

    for key in keys {
        if !js.has_key(key) {
            return false;
        }
    }
    true
}

/// Reads JSON from socket stream.
/// It uses `keys` to check the validity of the stream (if it contains the key(s) from `keys`).
///
/// Returns error if:
/// - Connection error.
/// - The stream format is invalid.
pub fn read_sized_json(socket: &mut TcpStream, keys: &[&str], size: usize) -> io::Result<json::JsonValue> {
    let data = read_sized_buffer(socket, size)?;
    let data = bytes_to_string(data.as_slice());

    let data_json = match json::parse(&data) {
        Ok(json) => json,
        Err(_) => {
            println!("{}", &data);
            warn!("Stream is not JSON");
            return Err(error_other!(Errors::WrongFormat))
        }
    };

    if !data_json.has_key("signal") && !check_json(&data_json, keys) {
        warn!("Invalid JSON format");
        return Err(error_other!(Errors::WrongFormat))
    }

    Ok(data_json)
}

pub fn get_accept_input() -> io::Result<char> {
    let mut input = [0; 1];
    io::stdout().flush()?;
    print!("Someone wants to send you a file (y/n/b): ");
    io::stdin().read_exact(&mut input)?;

    let res = input[0] as char;
    Ok(
        if ['y', 'b'].contains(&res) {res} else {'n'}
        )
}
