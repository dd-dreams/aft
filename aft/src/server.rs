//! Handling middle server functionality.
use crate::{
    constants::{
        CLIENT_RECV, MAX_CONTENT_LEN, MAX_IDENTIFIER_LEN, MAX_METADATA_LEN, SERVER, SHA_256_LEN,
        SIGNAL_LEN,
    },
    database::Database,
    utils::{bytes_to_string, new_ip, Signals},
};
use aft_crypto::{
    data::{SData, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE},
    exchange::KEY_LENGTH,
    password_encryption::create_hash,
};
use log::{debug, error, info};
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

enum StatusSender {
    Null,
    Blocked,
    Rejected,
}

/// Represents a server, which negotiates between clients or client to server.
pub struct Server {
    address: SocketAddr,
    db: Database,
}

impl Server {
    /// Creates a new Server struct.
    pub async fn new(port: u16, pguser: &str, pgpass: SData<String>) -> Self {
        Server {
            address: SocketAddr::new(new_ip!(""), port),
            db: Database::new(pguser, &pgpass.0).await.expect("Couldn't connect to database.")
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
        io::Result<StatusSender>
    {
        let mut receiver: TcpStream;
        {
            // If the receiver is not online
            if !Self::is_ident_exists(clients.clone(), recv_identifier).await {
                info!("{} is not online", recv_identifier);
                sender.write_all(Signals::Error.as_bytes()).await?;
                return Ok(StatusSender::Null);
            } else {
                // The receiver is online
                sender.write_all(Signals::OK.as_bytes()).await?;
            }

            receiver = clients.write().await.remove(recv_identifier).unwrap();
        }

        // Read signal from the sender
        let signal = read_signal(sender).await?;
        receiver.write_all(signal.as_bytes()).await?;
        // Write the sender's identifier
        receiver.write_all(sen_identifier.as_bytes()).await?;

        let acceptance = read_signal(&mut receiver).await?;

        // Write to sender if the receiver accepted the file transfer
        sender.write_all(acceptance.as_bytes()).await?;

        match acceptance {
            Signals::Error => {
                // Keep the receiver listening
                clients.write().await.insert(recv_identifier.to_string(), receiver);
                return Ok(StatusSender::Rejected)
            },
            Signals::Other => {
                clients.write().await.insert(recv_identifier.to_string(), receiver);
                return Ok(StatusSender::Blocked)
            },
            Signals::OK => (),
            s => {
                error!("Invalid signal: {}", s);
                return Ok(StatusSender::Null);
            }
        }

        Server::read_both_pks(sender, &mut receiver).await?;

        process_proxied(sender, &mut receiver).await?;

        Ok(StatusSender::Null)
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
            return true;
        }
        false
    }

    async fn read_and_hash_pass(socket: &mut TcpStream, salt: &[u8]) -> io::Result<String> {
        let mut pass = [0; SHA_256_LEN];
        socket.read_exact(&mut pass).await?;

        let pass_phc = match create_hash(&pass, Some(salt)) {
            Err(e) => {
                error!("Couldn't hash password. {}", e);
                return Ok(String::new());
            }
            Ok(v) => v,
        };

        Ok(pass_phc.to_string())
    }

    async fn read_identifier(socket: &mut TcpStream) -> io::Result<String> {
        let mut identifier = [0; MAX_IDENTIFIER_LEN];
        socket.read_exact(&mut identifier).await?;

        Ok(bytes_to_string(&identifier))
    }

    async fn handle_register(&mut self, socket: &mut TcpStream, identifier: &str, pass_phc: &str) -> io::Result<()> {
        debug!("{} requests to register", identifier);
        if self.is_registered_db(identifier).await {
            debug!("{} is already registered.", &identifier);
            socket.write_all(Signals::Error.as_bytes()).await?;
        } else {
            debug!("Registering {}", identifier);
            self.register_ident_db(identifier, pass_phc).await;
            debug!("{} is now registered", &identifier);
            socket.write_all(Signals::OK.as_bytes()).await?;
        }

        Ok(())
    }

    async fn handle_login(&self, socket: &mut TcpStream, identifier: &str, pass_phc: &str) -> io::Result<()> {
        debug!("{} requests to login", identifier);
        if !self.is_registered_db(identifier).await {
            info!("{} does not exist", identifier);
            // Invalid identifier
            socket.write_all(Signals::Error.as_bytes()).await?;
        } else {
            let db_phc_string = self.db.get_scryptd_ident(identifier).await.expect("Database error.");
            if pass_phc == db_phc_string {
                socket.write_all(Signals::OK.as_bytes()).await?;
            } else {
                // Invalid password
                error!("{}: invalid password", identifier);
                socket.write_all(Signals::Error.as_bytes()).await?;
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
                let identifier =
                    error_connection!(Server::read_identifier(&mut socket).await, return);
                // TODO: Send an error maybe?
                if identifier.is_empty() {
                    return;
                }

                let pass_phc = error_connection!(
                    Server::read_and_hash_pass(&mut socket, identifier.as_bytes()).await,
                    return
                );
                // If the server couldn't hash the password, then return.
                if pass_phc.is_empty() {
                    return;
                }

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
                            error_connection!(
                                socket.write_all(Signals::Unknown.as_bytes()).await,
                                return
                            );
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
                        error_connection!(socket.write_all(Signals::Error.as_bytes()).await, return);
                    }

                    // Remove the current connected one
                    if let Some(mut sock) = hashmap_writable.remove(&identifier) {
                        error_connection!(sock.shutdown().await, return);
                    } else {
                        error_connection!(socket.write_all(Signals::Error.as_bytes()).await, return);
                    }
                    // Add the new one
                    hashmap_writable.insert(identifier, socket);
                }
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

                if server.read().await.db.check_block(
                    &recv_identifier, &error_connection!(socket.peer_addr(), return).ip().to_string()).await.expect("Database error.") {
                    // Signaling to the sender that he is blocked
                    error_connection!(socket.write_all(Signals::Error.as_bytes()).await, return);
                    return;
                }

                let status = error_connection!(Server::handle_sender(&mut socket, clients, &recv_identifier, &sen_identifier).await, return);
                if let StatusSender::Blocked = status {
                    server.write().await.db.add_block(
                        &recv_identifier,
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
