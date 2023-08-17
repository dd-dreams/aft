//! Downloader.
use tokio::net::TcpStream;
use std::io;


pub struct Downloader {
    socket: TcpStream,
    identifier: String
}


impl Downloader {
    pub async fn new(ip: &str, identifier: &str) -> io::Result<Self> {
        Ok(
            Downloader {
                socket: TcpStream::connect(ip).await?,
                identifier: identifier.to_string()
            }
        )
    }
}

