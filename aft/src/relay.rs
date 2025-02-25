//! Handling relay functionality.
use crate::{
    constants::{CLIENT_RECV, MAX_IDENTIFIER_LEN, RELAY, SIGNAL_LEN},
    utils::{bytes_to_string, Signals},
};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};
use whirlwind::ShardMap;


type Identifier = String;
type ClientsHashMap = ShardMap<Identifier, TcpStream>;

macro_rules! error_conn {
    ($comm:expr, $ip:expr) => {
        error_conn!($comm, $ip, return)
    };
    ($comm:expr, $ip:expr, $step:expr) => {
        match $comm {
            Ok(v) => v,
            Err(e) => {
                error!("Connection error: {:?} {}", e, $ip);
                $step;
            }
        }
    };
}

async fn handle_sender(sender: &mut TcpStream, clients: Arc<ClientsHashMap>, recv_identifier: &String, sen_identifier: &str) ->
    io::Result<bool>
{
    let mut receiver;
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

        receiver = clients.remove(recv_identifier).await.unwrap();
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
            clients.insert(recv_identifier.to_string(), receiver).await;
            return Ok(false)
        },
        Signals::OK =>
            debug!("{} accepted request from {}. Transfer started.", recv_identifier, sender_ip),
        s => {
            error!("Invalid signal: {}", s);
            return Ok(false);
        }
    }

    copy_bidirectional(sender, &mut receiver).await?;

    Ok(true)
}

pub async fn is_ident_exists(clients: Arc<ClientsHashMap>, identifier: &String) -> bool {
    clients.contains_key(identifier).await
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
    let hashmap_clients = Arc::new(ClientsHashMap::new());

    info!("Listening ...");
    loop {
        let (mut socket, addr) = error_conn!(listener.accept().await, "", continue);
        info!("New connection from: {:?}", addr);

        let clients = hashmap_clients.clone();
        tokio::spawn(async move {
            // Write to the socket that its connecting to a relay
            error_conn!(socket.write_u8(RELAY).await, addr);

            // Read what the client wants: download or sending
            let command = error_conn!(socket.read_u8().await, addr);
            if command == CLIENT_RECV {
                let identifier = error_conn!(read_identifier(&mut socket).await, addr);
                if identifier.is_empty() {
                    debug!("{} provided invalid identifier", addr);
                    return;
                }

                if let Some(mut recv_sock) = clients.get_mut(&identifier).await {
                    // Connectivity check
                    error_conn!(recv_sock.write_all(Signals::Other.as_bytes()).await, addr);

                    if recv_sock.read_u8().await.is_err() {
                        debug!("{} disconnected", identifier);
                        clients.remove(&identifier).await;
                    } else {
                        debug!("Signaling to {}: \"{}\" identifier is not available", addr, identifier);
                        // Signal that someone is already connected with this identifier
                        error_conn!(socket.write_all(Signals::Error.as_bytes()).await, addr);
                        return;
                    }
                }
                clients.insert(identifier, socket).await;
            }
            // The sender (socket = sender)
            else {
                // Read the receiver's identifier
                let recv_identifier = error_conn!(read_identifier(&mut socket).await, addr);
                // Read the sender's identifier
                let sen_identifier = error_conn!(read_identifier(&mut socket).await, addr);
                if recv_identifier.is_empty() || sen_identifier.is_empty() {
                    debug!("Invalid identifier/s from {}", addr);
                    return;
                }

                error_conn!(
                    handle_sender(&mut socket, clients, &recv_identifier, &sen_identifier).await,
                    addr);
            }
        });
    }
}

async fn read_signal(socket: &mut TcpStream) -> io::Result<Signals> {
    let mut signal = [0u8; SIGNAL_LEN];
    socket.read_exact(&mut signal).await?;
    let signal = bytes_to_string(&signal);
    Ok(signal.as_str().into())
}
