//! Handling middle server functionality.
use crate::{
    constants::{
        CLIENT_RECV, MAX_CONTENT_LEN, MAX_IDENTIFIER_LEN, MAX_METADATA_LEN, SERVER, SIGNAL_LEN,
    },
    utils::{bytes_to_string, new_ip, Signals},
};
use aft_crypto::{
    data::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE},
    exchange::KEY_LENGTH,
};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const NONCE_TAG_LEN: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

type Identifier = String;
type ClientsHashMap = HashMap<Identifier, TcpStream>;
/// Moveable type between threads.
type MovT<T> = Arc<RwLock<T>>;

macro_rules! error_connection {
    ($comm:expr) => {
        if let Err(e) = $comm {
            error!("Error in connection: {:?}", e);
        }
    };
    ($comm:expr, $err_comm:expr) => {
        match $comm {
            Err(e) => {
                error!("Error in connection: {:?}", e);
                $err_comm;
            }
            Ok(v) => v,
        }
    };
}

/// Represents a server, which negotiates between clients or client to server.
pub struct Server {
    address: SocketAddr,
}

impl Server {
    /// Creates a new Server struct.
    pub async fn new(port: u16) -> Self {
        Server {
            address: SocketAddr::new(new_ip!(""), port),
        }
    }

    async fn read_both_pks(sender: &mut TcpStream, receiver: &mut TcpStream) -> io::Result<()> {
        // Write to the sender the receiver's public key
        let mut receiver_pk = [0u8; KEY_LENGTH];
        receiver.read_exact(&mut receiver_pk).await?;
        sender.write_all(&receiver_pk).await?;

        // Write to the receiver the sender's public key
        let mut sender_pk = [0u8; KEY_LENGTH];
        sender.read_exact(&mut sender_pk).await?;
        receiver.write_all(&sender_pk).await?;

        Ok(())
    }

    async fn handle_sender(sender: &mut TcpStream, clients: MovT<ClientsHashMap>, recv_identifier: &str, sen_identifier: &str) ->
        io::Result<bool>
    {
        let mut receiver: TcpStream;
        {
            // If the receiver is not online
            if !Self::is_ident_exists(clients.clone(), recv_identifier).await {
                info!("{} is not online", recv_identifier);
                sender.write_all(Signals::Error.as_bytes()).await?;
                return Ok(false);
            } else {
                // The receiver is online
                sender.write_all(Signals::OK.as_bytes()).await?;
            }

            receiver = clients.write().await.remove(recv_identifier).unwrap();
        }

        // Read signal from the sender
        let signal = read_signal(sender).await?;
        receiver.write_all(signal.as_bytes()).await?;

        let hashed_sen_ip = {
            let mut sha = Sha256::new();
            sha.update(sender.peer_addr()?.ip().to_string());
            sha.finalize()
        };
        // Write the sender's identifier
        receiver.write_all(sen_identifier.as_bytes()).await?;
        // Write to the sender the hashed IP of the sender's, so he can continue blocking
        // him.
        receiver.write_all(&hashed_sen_ip).await?;

        let acceptance = read_signal(&mut receiver).await?;

        // Write to sender if the receiver accepted the file transfer
        sender.write_all(acceptance.as_bytes()).await?;

        match acceptance {
            Signals::Error => {
                info!("{} rejected {}", recv_identifier, sen_identifier);
                // Keep the receiver listening
                clients.write().await.insert(recv_identifier.to_string(), receiver);
                return Ok(false)
            },
            Signals::OK => (),
            s => {
                error!("Invalid signal: {}", s);
                return Ok(false);
            }
        }

        Server::read_both_pks(sender, &mut receiver).await?;

        process_proxied(sender, &mut receiver).await?;

        Ok(true)
    }

    pub async fn is_ident_exists(clients: MovT<ClientsHashMap>, identifier: &str) -> bool {
        if clients.read().await.contains_key(identifier) {
            return true;
        }
        false
    }

    async fn read_identifier(socket: &mut TcpStream) -> io::Result<String> {
        let mut identifier = [0; MAX_IDENTIFIER_LEN];
        socket.read_exact(&mut identifier).await?;

        Ok(bytes_to_string(&identifier))
    }
}

/// Initializes the server and starts receiving connections.
///
/// Error when there is a connection error.
pub async fn init(server: Server) -> io::Result<()> {
    let listener = TcpListener::bind(server.address.to_string()).await?;
    let hashmap_clients = Arc::new(RwLock::new(ClientsHashMap::new()));

    info!("Listening ...");
    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New connection from: {:?}", addr);

        async fn call(clients: MovT<ClientsHashMap>, mut socket: TcpStream) {
            // Write to the socket that its connecting to a server
            error_connection!(socket.write_u8(SERVER).await, return);

            // Read what the client wants: download or sending
            let command = error_connection!(socket.read_u8().await, return);
            if command == CLIENT_RECV {
                let identifier =
                    error_connection!(Server::read_identifier(&mut socket).await, return);
                if identifier.is_empty() {
                    return;
                }

                let mut clients_writeable = clients.write().await;
                if let Some(recv_sock) = clients_writeable.get_mut(&identifier) {
                    // Connectivity check
                    error_connection!(recv_sock.write_all(Signals::Other.as_bytes()).await);
                    if recv_sock.read_u8().await.is_err() {
                        debug!("{} disconnected", identifier);
                        clients_writeable.remove(&identifier);
                    } else {
                        // Signal that someone is already connected with this identifier
                        error_connection!(socket.write_all(Signals::Error.as_bytes()).await);
                        return;
                    }
                }
                clients_writeable.insert(identifier, socket);
            }
            // The sender (socket = sender)
            else {
                // Read the receiver's identifier
                let recv_identifier =
                    error_connection!(Server::read_identifier(&mut socket).await, return);
                // Read the sender's identifier
                let sen_identifier =
                    error_connection!(Server::read_identifier(&mut socket).await, return);
                if recv_identifier.is_empty() || sen_identifier.is_empty() {
                    return;
                }

                error_connection!(
                    Server::handle_sender(&mut socket, clients, &recv_identifier, &sen_identifier).await);
            }
        }

        tokio::spawn(call(hashmap_clients.clone(), socket));
    }
}

/// Handles connections when the sender and receiver connects to the server to communicate.
///
/// Returns the signal the client has ended with.
/// Error when there was a connection problem.
async fn process_proxied(sender: &mut TcpStream, receiver: &mut TcpStream) -> io::Result<Signals> {
    let mut metadata = [0; MAX_METADATA_LEN + NONCE_TAG_LEN];
    sender.read_exact(&mut metadata).await?;
    // Write metadata to receiver
    receiver.write_all(&metadata).await?;

    info!("Received a transfer request from {} to {}", sender.peer_addr()?.ip(), receiver.peer_addr()?.ip());
    let mut file_current_size = [0u8; 8 + NONCE_TAG_LEN];
    // Read from the receiver the file size
    receiver.read_exact(&mut file_current_size).await?;
    // Send the file size to the sender, so he will know where to start
    sender.write_all(&file_current_size).await?;

    let mut buffer = [0; MAX_CONTENT_LEN + NONCE_TAG_LEN];
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
