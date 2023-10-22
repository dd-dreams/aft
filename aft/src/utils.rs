/// Module for various utilities used in other modules.
use std::{
    fs::{self, File},
    io::{
        self,
        prelude::*,
        SeekFrom
    },
    net::{TcpStream, Ipv4Addr}
};
use log::{info, debug, error};
use sha2::{Sha256, Digest};
use crate::constants::MAX_IDENTIFIER_LEN;

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


macro_rules! mut_vec {
    ($s:expr) => {&mut $s.to_vec()}
} pub(crate) use mut_vec;

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

    /// Seeks to the start + pos.
    pub fn seek_start(&mut self, pos: u64) -> io::Result<u64> {
        self.file.seek(SeekFrom::Start(pos))
    }

    /// Seeks to the end - pos.
    pub fn seek_end(&mut self, pos: i64) -> io::Result<u64> {
        self.file.seek(SeekFrom::End(pos))
    }

    /// Returns the current cursor position in file.
    pub fn get_index(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    /// Returns the length of the file.
    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Returns whether the file is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Checks if a file exists.
    pub fn is_file_exists(path: &str) -> bool {
        std::path::Path::new(path).is_file()
    }

    /// Returns the current checksum of the file.
    pub fn checksum(&self) -> Vec<u8> {
        self.hasher.clone().finalize().to_vec()
    }

    /// Updates the checksum.
    pub fn update_checksum(&mut self, buffer: &[u8]) {
        self.hasher.update(buffer);
    }

    /// Resets the checksum.
    pub fn reset_checksum(&mut self) {
        self.hasher.reset();
    }

    /// Removes a file.
    pub fn rm(path: &str) -> io::Result<()> {
        fs::remove_file(path)
    }

    /// Rename `filename` to `new_filename`.
    pub fn rename(filename: &str, new_filename: &str) -> io::Result<()> {
        fs::rename(filename, new_filename)
    }
}

/// Transforms bytes slice to a string (&str).
pub fn bytes_to_string(buffer: &[u8]) -> String {
    String::from_utf8_lossy(buffer).to_string()
}

/// Prints a progress bar.
pub fn progress_bar(pos: u8, max: u8) {
    io::stdout().flush().unwrap();
    if pos == max {
        // clear screen
        print!("\r\n");
    } else {
        print!("\r[{}>{}] {}%", "=".repeat(pos as usize), " ".repeat((max-1 - pos) as usize), pos*2+2);
    }
}

/// Adds to the progress bar a download speed.
pub fn download_speed(bytes_sent: usize) {
    let mb: f32 = bytes_sent as f32 / 1000000.0;
    print!("  {:.2}MB/s", mb);
}

pub fn get_input(msg: &str) -> io::Result<String> {
    let mut input = String::new();
    print!("{}", msg);
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    // Removing \n
    input.pop();

    Ok(input)
}

pub fn get_accept_input(msg: &str) -> io::Result<char> {
    let res = get_input(msg)?.chars().next().unwrap_or_default();
    Ok(
        if ['y', 'b'].contains(&res) {res} else {'n'}
        )
}

/// Sends an identifier through a socket.
///
/// Returns false if the identifier is too long.
pub fn send_identifier(ident: &[u8], socket: &mut TcpStream) -> io::Result<bool> {
    if ident.len() != MAX_IDENTIFIER_LEN {
        error!("Identifier length != 10.");
        return Ok(false)
    }
    // Write the identifier of this receiver
    socket.write(ident)?;

    Ok(true)
}

pub fn get_pub_ip() -> io::Result<String> {
    let mut stream = TcpStream::connect("api.ipify.org:80")?;
    let request = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nAccept: */*\r\n\r\n".as_bytes();

    stream.write_all(request)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let addr = response.trim().split('\n').last().unwrap_or("Couldn't extract IP").to_string();

    Ok(addr)
}

pub fn ip_to_octets(ip_str: &str) -> [u8; 4] {
    let ip: Ipv4Addr = ip_str.parse().expect("IP format is incorrect.");
    ip.octets()
}
