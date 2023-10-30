//! Handling relay functionality.
use crate::{
    constants::{
        CLIENT_RECV, MAX_CONTENT_LEN, MAX_IDENTIFIER_LEN, MAX_METADATA_LEN, RELAY, SIGNAL_LEN,
    },
    utils::{bytes_to_string, Signals},
};
use aft_crypto::{
    data::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE},
    exchange::KEY_LENGTH,
};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io, sync::Arc};
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
    let sender_ip = sender.peer_addr()?;

    debug!("{} wants to transfer to {}", sen_identifier, recv_identifier);

    {
        // If the receiver is not online
        if !is_ident_exists(clients.clone(), recv_identifier).await {
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
            debug!("{} rejected {}", recv_identifier, sender_ip);
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

    read_both_pks(sender, &mut receiver).await?;

    process_transfer(sender, &mut receiver).await?;

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

/// Initializes the relay and starts receiving connections.
///
/// Error when there is a connection error.
pub async fn init(address: &str) -> io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    let hashmap_clients = Arc::new(RwLock::new(ClientsHashMap::new()));

    info!("Listening ...");
    loop {
        let (socket, addr) = listener.accept().await?;
        info!("New connection from: {:?}", addr);

        async fn call(clients: MovT<ClientsHashMap>, mut socket: TcpStream) -> io::Result<()> {
            // Write to the socket that its connecting to a relay
            socket.write_u8(RELAY).await?;

            let ip = socket.peer_addr()?;

            // Read what the client wants: download or sending
            let command = socket.read_u8().await?;
            if command == CLIENT_RECV {
                let identifier = read_identifier(&mut socket).await?;
                if identifier.is_empty() {
                    debug!("{} provided invalid identifier", ip);
                    return Ok(());
                }

                let mut clients_writeable = clients.write().await;
                if let Some(recv_sock) = clients_writeable.get_mut(&identifier) {
                    // Connectivity check
                    recv_sock.write_all(Signals::Other.as_bytes()).await?;
                    if recv_sock.read_u8().await.is_err() {
                        debug!("{} disconnected", identifier);
                        clients_writeable.remove(&identifier);
                    } else {
                        debug!("Signaling to {}: {} identifier is not available", ip, identifier);
                        // Signal that someone is already connected with this identifier
                        socket.write_all(Signals::Error.as_bytes()).await?;
                        return Ok(());
                    }
                }
                clients_writeable.insert(identifier, socket);
            }
            // The sender (socket = sender)
            else {
                // Read the receiver's identifier
                let recv_identifier = read_identifier(&mut socket).await?;
                // Read the sender's identifier
                let sen_identifier = read_identifier(&mut socket).await?;
                if recv_identifier.is_empty() || sen_identifier.is_empty() {
                    debug!("Invalid identifier/s from {}", ip);
                    return Ok(());
                }

                handle_sender(&mut socket, clients, &recv_identifier, &sen_identifier).await?;
            }

            Ok(())
        }

        let ip = socket.peer_addr();
        if let Err(e) = tokio::spawn(call(hashmap_clients.clone(), socket)).await {
            error!("Connection error with {:?}: {}", ip , e);
        }
    }
}

/// Processes the transfer between two peers.
///
/// Returns the signal the client has ended with.
/// Error when there was a connection problem.
async fn process_transfer(sender: &mut TcpStream, receiver: &mut TcpStream) -> io::Result<Signals> {
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
