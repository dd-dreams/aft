//! Handling server functionality (includes P2P).
//!
//! # Communication
//! ## Directly (Peer to Peer)
//! Peer to peer is where two clients connect to each other directly.
//! There is the _sender_ and the _receiver_ when a file is transferred between two devices.
//! The receiver starts by notifiying the sender that its connecting to a client that receives
//! files, the _receiver_. Then, the sender sends the metadata of the file and the receiver
//! does some checks, such as checking if a file with the same name exists already. After that,
//! the sender starts sending chunks of the file to the receiver.
//!
//! ## Proxied
//! In case where two clients don't want to connect to each other directly, a service can be used to
//! allow them to communicate indirectly. This service (the server), just forwards the communication
//! from the sender to the receiver and in the otherway.
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::{io, net::SocketAddr};
use crate::utils::{new_ip,
                   bytes_to_string,
                   error_other,
                   Signals};
use crate::constants::{MAX_CONTENT_LEN, MAX_METADATA_LEN, MAX_IDENTIFIER_LEN,
    SERVER, CLIENT_RECV, SIGNAL_LEN, PASS_LEN};
use crate::errors::Errors;
use log::{info, error, debug};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::database::Database;
use aft_crypto::{
    password_encryption::create_hash,
    exchange::KEY_LENGTH, data::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE}};


pub const UNFINISHED_FILE_MSG: &str = "undone";

pub type Identifier = String;
pub type ClientsHashMap = HashMap<Identifier, TcpStream>;
/// Moveable type between threads.
pub type MovT<T> = Arc<RwLock<T>>;

macro_rules! error_connection {
    ($comm:expr) => {
        match $comm {
            Err(e) => {error!("Error in connection: {:?}", e); continue;},
            Ok(v) => v
        }
    };
    ($comm:expr, $err_comm:expr) => {
        match $comm {
            Err(e) => {error!("Error in connection: {:?}", e); $err_comm;},
            Ok(v) => v
        }
    };
}

pub async fn read_sized_buffer(socket: &mut (impl AsyncReadExt + std::marker::Unpin), size: usize) -> Result<Vec::<u8>, io::Error> {
    // u64, because std::fs::metadata().len() returns u64
    let data_len = socket.read_u64_le().await? as usize;
    if data_len > size {
        // TODO: send error to socket.
        return Err(error_other!(Errors::BufferTooBig))
    }

    let mut data = vec![0u8; data_len];
    socket.read_exact(&mut data).await?;

    Ok(data)
}

/// Represents a server, which negotiates between clients or client to server.
pub struct Server {
    address: SocketAddr,
    db: Database
}

impl Server {
    /// Creates a new Server struct.
    pub async fn new(port: u16, pguser: &str, pgpass: &str) -> Self {
        if pguser.is_empty() || pgpass.is_empty() {
            // TODO
        }
        Server {
            address: SocketAddr::new(new_ip!(""), port),
            db: Database::new(pguser, pgpass).await.expect("Couldn't connect to database.")
        }
    }

    async fn read_both_pks(sender: &mut TcpStream, receiver: &mut TcpStream) -> io::Result<()> {
        // Write to the sender the receiver's public key
        let mut receiver_pk = [0u8; KEY_LENGTH];
        receiver.read(&mut receiver_pk).await?;
        sender.write_all(&receiver_pk).await?;

        // Write to the receiver the sender's public key
        let mut sender_pk = [0u8; KEY_LENGTH];
        sender.read(&mut sender_pk).await?;
        receiver.write_all(&sender_pk).await?;

        Ok(())
    }

    async fn handle_sender(sender: &mut TcpStream, clients: MovT<ClientsHashMap>, identifier: &str) ->
        io::Result<String>
    {
        let mut receiver: TcpStream;
        {
            // If the receiver is not online
            if !Self::is_ident_exists(clients.clone(), identifier).await {
                info!("{} is not online", identifier);
                sender.write(Signals::Error.as_bytes()).await?;
                return Ok("".to_string())
            } else {
                // Write to start the transfer
                sender.write(Signals::StartFt.as_bytes()).await?;
            }

            receiver = clients.write().await.remove(identifier).unwrap();
        }

        // Read signal from the sender
        let signal = read_signal(sender).await?;
        receiver.write(signal.as_bytes()).await?;

        let acceptance = read_signal(&mut receiver).await?;
        sender.write(acceptance.as_bytes()).await?;
        // Receiver blocked this sender.
        if acceptance == Signals::Other {
            return Ok(identifier.to_string());
        }

        Server::read_both_pks(sender, &mut receiver).await?;

        process_proxied(sender, &mut receiver).await?;

        // TODO
        Ok("".to_string())
    }

    async fn is_registered_db(&self, identifier: &str) -> bool {
        // TODO: Panic for now, but find some workaround like trying to reconnect or other.
        self.db.is_ident_exists(identifier).await.expect("Database is closed!")
    }

    async fn register_ident_db(&mut self, identifier: &str, pass: &str) {
        self.db.add_row(identifier, pass).await.expect("An error has occurred with the database.");
    }

    pub async fn is_ident_exists(clients: MovT<ClientsHashMap>, identifier: &str) -> bool {
        if clients.read().await.contains_key(identifier) {
            return true
        }
        false
    }

    async fn read_and_hash_pass(socket: &mut TcpStream, salt: &[u8]) -> io::Result<String> {
        let mut pass = read_sized_buffer(socket, PASS_LEN).await?;

        let pass_phc = match create_hash(&mut pass, Some(salt)) {
            Err(e) => {
                error!("Couldn't hash password. {}", e);
                return Ok(String::new());
            },
            Ok(v) => v
        };

        Ok(pass_phc.to_string())
    }

    async fn handle_register(&mut self, socket: &mut TcpStream, identifier: &str, pass_phc: &str) -> io::Result<()> {
        debug!("{} requests to register", identifier);
        if self.is_registered_db(identifier).await {
            debug!("{} is already registered.", &identifier);
            socket.write(Signals::Error.as_bytes()).await?;
        } else {
            debug!("Registering {}", identifier);
            self.register_ident_db(identifier, pass_phc).await;
            debug!("{} is now registered", &identifier);
            socket.write(Signals::OK.as_bytes()).await?;
        }

        Ok(())
    }

    async fn handle_login(&self, socket: &mut TcpStream, identifier: &str, pass_phc: &str) -> io::Result<()> {
        debug!("{} requests to login", identifier);
        if !self.is_registered_db(identifier).await {
            info!("{} does not exist", identifier);
            // Invalid identifier
            socket.write(Signals::Error.as_bytes()).await?;
        } else {
            let db_phc_string = self.db.get_scryptd_ident(identifier).await.expect("Database error.");
            if pass_phc == db_phc_string {
                socket.write(Signals::OK.as_bytes()).await?;
            } else {
                // Invalid password
                error!("{}: invalid password", identifier);
                socket.write(Signals::Error.as_bytes()).await?;
            }
        }

        Ok(())
    }
}

/// Initializes the server and starts receiving connections.
///
/// Error when there is a connection error.
pub async fn init(mut server: Server) -> io::Result<()> {
    let listener = TcpListener::bind(server.address.to_string()).await?;
    let hashmap_clients = Arc::new(RwLock::new(ClientsHashMap::new()));
    server.db.create_table().await.expect("Database error.");

    let server = Arc::new(RwLock::new(server));
    info!("Listening ...");
    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New connection from: {:?}", addr);

        async fn call(clients: MovT<ClientsHashMap>, mut socket: TcpStream, server: MovT<Server>) {
            // Write to the socket that its connecting to a server
            error_connection!(socket.write_u8(SERVER).await, return);

            // Read what the client wants: download or sending
            let command = error_connection!(socket.read_u8().await, return);
            if command == CLIENT_RECV {
                let identifier = bytes_to_string(
                    &error_connection!(read_sized_buffer(&mut socket, MAX_IDENTIFIER_LEN).await, return)
                    );
                let pass_phc = error_connection!(Server::read_and_hash_pass(&mut socket, identifier.as_bytes()).await, return);

                if !Server::is_ident_exists(clients.clone(), &identifier).await {
                    let signal = error_connection!(read_signal(&mut socket).await, return);
                    match signal {
                        Signals::Register => {
                            error_connection!(server.write().await.handle_register(&mut socket, &identifier, &pass_phc).await, return);
                        },
                        Signals::Login => {
                            error_connection!(server.read().await.handle_login(&mut socket, &identifier, &pass_phc).await, return);
                        },
                        _ => {
                            debug!("Invalid signal: {}", signal.as_str());
                            error_connection!(socket.write(Signals::Unknown.as_bytes()).await, return);
                        }
                    }
                    clients.write().await.insert(identifier, socket);
                // There is already someone connected (in the hashmap). Disconnect him and add this
                // one.
                } else {
                    let mut hashmap_writable = clients.write().await;
                    // The client now must choose a Login signal, since if someone was connected
                    // with this identifier, he must've registered.
                    let signal = error_connection!(read_signal(&mut socket).await, return);

                    if signal == Signals::Login {
                        error_connection!(server.read().await.handle_login(&mut socket, &identifier, &pass_phc).await, return);
                    } else {
                        debug!("Invalid signal: {}", signal.as_str());
                        error_connection!(socket.write(Signals::Error.as_bytes()).await, return);
                    }

                    // Remove the current connected one
                    if let Some(mut sock) = hashmap_writable.remove(&identifier) {
                        error_connection!(sock.shutdown().await, return);
                    } else {
                        error_connection!(socket.write(Signals::Error.as_bytes()).await, return);
                    }
                    // Add the new one
                    hashmap_writable.insert(identifier, socket);
                }
            }
            // The sender
            else {
                // Read the receiver's identifier
                let identifier = bytes_to_string(error_connection!(&read_sized_buffer(&mut socket, MAX_IDENTIFIER_LEN).await, return));

                if server.read().await.db.check_block(
                    &identifier, error_connection!(socket.peer_addr(), return).ip().to_string().as_str()).await.expect("Database error.") {
                    error_connection!(socket.write(Signals::Error.as_bytes()).await, return);
                    return;
                }

                let res = error_connection!(Server::handle_sender(&mut socket, clients, &identifier).await, return);
                if !res.is_empty() {
                    server.write().await.db.add_block(
                        &res,
                        error_connection!(socket.peer_addr(), return).ip().to_string().as_str()
                        ).await.expect("Database error.");
                }
            }
        }

        tokio::spawn(call(hashmap_clients.clone(), socket, server.clone()));
    }
}

/// Handles connections when the sender and receiver connects to the server to communicate.
///
/// Returns the signal the client has ended with.
/// Error when there was a connection problem.
async fn process_proxied(sender: &mut TcpStream, receiver: &mut TcpStream) ->
    io::Result<Signals>
{
    // TODO: simplify arrays sizes by using another constant
    let mut metadata = [0; MAX_METADATA_LEN + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE];
    let read_bytes = sender.read(&mut metadata).await?;
    // Write metadata to receiver
    receiver.write_all(&metadata[..read_bytes]).await?;

    info!("Received a transfer request from {} to {}", sender.peer_addr()?.ip(), receiver.peer_addr()?.ip());
    let mut file_current_size = [0u8; 8 + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE];
    // Read from the receiver the file size
    receiver.read_exact(&mut file_current_size).await?;
    // Send the file size to the sender, so he will know where to start
    sender.write_all(&file_current_size).await?;

    let mut buffer = [0; MAX_CONTENT_LEN + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE];
    loop {
        match sender.read_exact(&mut buffer).await {
            Ok(_) => (),
            Err(_) => {
                // Wait for everything to be written
                receiver.shutdown().await?;
                break;
            }
        };
        match receiver.write_all(&buffer).await {
            Ok(_) => (),
            Err(_) => {
                break;
            }
        };
    }
    info!("{} -> {} finished successfully", sender.peer_addr()?, receiver.peer_addr()?);

    Ok(Signals::EndFt)
}

async fn read_signal(socket: &mut TcpStream) -> io::Result<Signals> {
    let mut signal = [0u8; SIGNAL_LEN];
    socket.read_exact(&mut signal).await?;
    let signal = bytes_to_string(&signal);
    Ok(signal.as_str().into())
}
