//! Handling sender.
use crate::{
    clients::{BaseSocket, Crypto, SWriter},
    constants::{
        CLIENT_SEND, MAX_CHECKSUM_LEN, MAX_CONTENT_LEN, MAX_METADATA_LEN, SERVER, SIGNAL_LEN,
    },
    errors,
    utils::{
        download_speed, error_other, mut_vec, progress_bar, send_identifier, FileOperations,
        Signals,
    },
};
use aft_crypto::{
    data::{AeadInPlace, EncAlgo, SData},
    exchange::{PublicKey, KEY_LENGTH},
};
use json;
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::SystemTime,
};

fn update_pb(curr_bars_count: &mut u8, pb_length: u64, bytes_transferred: u64) {
    *curr_bars_count = (bytes_transferred / (pb_length + 1)).try_into().unwrap_or(0);
    progress_bar(*curr_bars_count, 50);
}

fn basic_file_checks(path: &Path) -> io::Result<bool> {
    if path.metadata()?.len() == 0 {
        error!("File is empty");
        return Ok(false);
    }

    if path.extension().is_none() {
        warn!("No file extension.");
    }

    if path.is_dir() {
        error!("Inputted a name of a directory and not a file");
        return Err(error_other!("Not a file"));
    }

    Ok(true)
}

/// A struct that represents a sender.
pub struct Sender<T> {
    // TODO: Handle domains.
    writer: SWriter<T>,
    file_path: String,
    current_pos: u64,
    identifier: String,
    gen_encryptor: fn(&[u8]) -> T,
}

impl<T> BaseSocket<T> for Sender<T>
where
    T: AeadInPlace,
{
    fn get_writer(&self) -> &SWriter<T> {
        &self.writer
    }

    fn get_mut_writer(&mut self) -> &mut SWriter<T> {
        &mut self.writer
    }

    fn shared_secret(&mut self) -> io::Result<()> {
        let shared_key = self.gen_shared_secret()?;
        self.writer.1 = EncAlgo::new(shared_key.as_bytes(), self.gen_encryptor);
        Ok(())
    }
}

impl<T> Crypto for Sender<T> {
    fn exchange_pk(&mut self, pk: PublicKey) -> io::Result<PublicKey> {
        let mut other_pk = [0; 32];

        // Getting endpoint's public key
        debug!("Getting public key");
        self.writer.0.read_exact(&mut other_pk)?;
        // Writing the public key
        debug!("Writing public key");
        self.writer.0.write_all(pk.as_bytes())?;

        Ok(PublicKey::from(other_pk))
    }
}

impl<T> Sender<T>
where
    T: AeadInPlace,
{
    /// Constructs a new Sender struct, and connects to `remote_ip`.
    pub fn new(remote_addr: &str, ident: String, encryptor_func: fn(&[u8]) -> T) -> Self {
        // Remove http(s):// since aft doesn't support HTTPS.
        let no_http_addr = remote_addr.replace("http://", "").replace("https://", "");
        let socket = TcpStream::connect(no_http_addr.to_socket_addrs().expect("Couldn't resolve IP").next()
            .expect("IP Not resolved"))
            .expect("Couldn't connect.");
        Sender {
            writer: SWriter(socket, EncAlgo::<T>::new(&[0u8; KEY_LENGTH], encryptor_func)),
            file_path: String::new(),
            current_pos: 0,
            identifier: ident,
            gen_encryptor: encryptor_func,
        }
    }

    /// Signals to the endpoint to start the file transfer process.
    fn signal_start(&mut self) -> io::Result<()> {
        self.get_mut_writer().0.write(Signals::StartFt.as_bytes())?;
        Ok(())
    }

    /// If the sender is connecting to a server (a proxy).
    ///
    /// # Errors
    /// When there is a connection error.
    ///
    /// Returns false when the identifier is too long.
    fn if_server(&mut self, rece_ident: &str, sen_ident: &str) -> io::Result<bool> {
        // Notify the server that this sender is sending data
        self.writer.0.write(&[CLIENT_SEND])?;
        // Write the receiver's identifier
        Ok(send_identifier(rece_ident.as_bytes(), &mut self.writer.0)?
            // Write the sender's identifier
            && send_identifier(sen_ident.as_bytes(), &mut self.writer.0)?)
    }

    fn get_starting_pos(&mut self) -> io::Result<()> {
        // Starting position from receiver
        let mut file_pos_bytes = vec![0u8; 8];
        debug!("Getting starting position ...");
        self.writer.read_ext(&mut file_pos_bytes)?;
        self.current_pos = u64::from_le_bytes(file_pos_bytes.try_into().unwrap_or_default());
        debug!("Starting position: {}", self.current_pos);

        Ok(())
    }

    pub fn auth(&mut self, pass: &str) -> io::Result<bool> {
        let pass_hashed = {
            let mut sha = Sha256::new();
            sha.update(pass);
            sha.finalize()
        };

        debug!("Authenticating ...");
        self.writer.write_ext(mut_vec!(pass_hashed))?;

        Ok(self.read_signal()? == Signals::OK)
    }

    /// Initial connection sends a JSON data formatted, with some metadata.
    /// It will usually look like the following:
    /// ```json
    /// {
    ///     "metadata": {
    ///         "filetype": "<filetype>",
    ///         "filename": "<filename>",
    ///         "size": "<file size in bytes>",
    ///         "modified": "<date>"
    ///     },
    ///     "sender": {
    ///         "identifier": "<identifier>"
    ///     }
    /// }
    /// ```
    /// Make sure `socket` is still valid and have not disconnected.
    ///
    /// Returns true if the transfer completed successfully, else false.
    ///
    /// Returns error when:
    /// - `path` doesn't exist.
    /// - Connection error.
    /// - JSON metadata is too big when one of the following are too big:
    ///     - Filetype.
    ///     - Filename.
    ///     - File size.
    ///     - Modified date.
    ///     - Identifier of the sender.
    ///
    ///
    /// Returns false if something went wrong (such as the identifier is too long, or when the
    /// receiver isn't online).
    pub fn init_send(&mut self, path: &str, sen_ident: &str, receiver_identifier: Option<&str>, pass: SData<String>) -> io::Result<bool> {
        let file_path = Path::new(path);

        if !basic_file_checks(file_path)? {
            return Ok(false);
        }

        self.file_path = path.to_string();

        let mut server_or_receiver = [0u8; 1];
        self.writer.0.read_exact(&mut server_or_receiver)?;
        if server_or_receiver[0] == SERVER {
            debug!("Connected to a server");
            if let Some(ident) = receiver_identifier {
                // If the identifier is too long
                if !self.if_server(ident, sen_ident)? {
                    return Ok(false);
                }
                // Read signal
                match self.read_signal_server()? {
                    Signals::OK => (),
                    Signals::Error => {
                        error!("Receiver is not online.");
                        return Ok(false);
                    }
                    s => {
                        error!("Unexepected signal: {}", s);
                        return Ok(false);
                    }
                }
            } else {
                return Err(error_other!(errors::Errors::NoReceiverIdentifier));
            }

            debug!("Signaling to start");
            // Write to the endpoint to start the transfer
            self.signal_start()?;

            match self.read_signal_server()? {
                Signals::OK => info!("Reciever accepted."),
                Signals::Error => {
                    error!("Receiver rejected.");
                    return Ok(false);
                }
                s => {
                    error!("Received invalid signal: {}", s);
                    return Ok(false);
                }
            }

            self.shared_secret()?;
        } else {
            self.shared_secret()?;
            if !self.auth(&pass.0)? {
                error!("Incorrect password.");
                return Ok(false);
            }
        }

        let parsed = json::object! {
            metadata: {
                filetype: file_path.extension().unwrap_or_default().to_str().unwrap(),
                filename: file_path.file_name().unwrap().to_str().unwrap(),
                size: file_path.metadata()?.len(),
                modified: file_path.metadata()?.modified()?.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
            },
            sender: {
                identifier: self.identifier.as_str()
            }
        };

        if parsed.dump().len() > MAX_METADATA_LEN {
            error!("Metadata size is too big");
            return Err(error_other!(errors::Errors::BufferTooBig));
        }

        let dump = parsed.dump();
        let metadata_vec_bytes = dump.as_bytes();
        let mut full_metadata = vec![0; MAX_METADATA_LEN];
        full_metadata[..metadata_vec_bytes.len()].copy_from_slice(metadata_vec_bytes);

        // Write metadata
        debug!("Sending metadata");
        self.writer.write_ext(&mut full_metadata)?;

        self.get_starting_pos()?;
        Ok(true)
    }

    /// After the *initial connection*, we send chunks. Every chunk is the data of the file.
    ///
    /// Returns error when a connection error has occurred.
    pub fn send_chunks(&mut self) -> io::Result<()> {
        let mut file = FileOperations::new(&self.file_path)?;
        file.seek_start(self.current_pos)?;

        let mut curr_bars_count = 0u8;
        // Add a new bar to progress bar when x bytes have been transferred
        let pb_length = file.len()? / 50;

        debug!("Writing chunks");
        if self.current_pos != 0 {
            update_pb(&mut curr_bars_count, pb_length, self.current_pos);
        }

        let system_time = SystemTime::now();
        let mut before = 0;
        let mut bytes_sent_sec = 0;

        let mut buffer = vec![0; MAX_CONTENT_LEN];
        loop {
            let read_size = file.read_seek_file_sized(&mut buffer)?;
            // If we reached EOF
            if read_size == 0 {
                break;
            }

            bytes_sent_sec += read_size;
            self.current_pos += read_size as u64;

            // It's fine to include the 0's if there are any in `buffer` (only happens on the last
            // chunk of the file).
            file.update_checksum(&buffer);

            self.writer.write_ext(&mut buffer)?;

            // Progress bar
            update_pb(&mut curr_bars_count, pb_length, self.current_pos);

            match system_time.elapsed() {
                Ok(elapsed) => {
                    // update the download speed every 1 second
                    if elapsed.as_secs() != before {
                        before = elapsed.as_secs();
                        download_speed(bytes_sent_sec);
                        bytes_sent_sec = 0;
                    }
                }
                Err(e) => error!("An error occurred while printing download speed: {}", e),
            }
        }

        println!();
        debug!("Reached EOF");
        debug!("Ending file transfer and writing checksum");
        buffer[..SIGNAL_LEN].copy_from_slice(Signals::EndFt.as_bytes());
        buffer[SIGNAL_LEN..MAX_CHECKSUM_LEN + SIGNAL_LEN].copy_from_slice(&file.checksum());
        self.writer.write_ext(&mut buffer)?;
        info!("Finished successfully");

        Ok(())
    }
}
