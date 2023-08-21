//! Handling sender.
use std::{io,
    net::TcpStream,
    path::Path
};
use std::io::{Write, Read};
use json;
use log::{error, warn, info, debug};
use sha2::{Sha256, Digest};
use crate::utils::{write_sized_buffer, FileOperations, error_other, progress_bar, Signals};
use crate::errors;
use crate::constants::{MAX_METADATA_LEN, MAX_CONTENT_LEN, SERVER, CLIENT_SEND, MAX_CHECKSUM_LEN, SIGNAL_LEN};
use crate::clients::{BaseSocket, Crypto, SWriter};
use aft_crypto::{exchange::{PublicKey, KEY_LENGTH},
    data::{EncAlgo, AeadInPlace}};

fn update_pb(curr_bars_count: &mut u8, pb_length: u64, bytes_transferred: u64) {
    *curr_bars_count = (bytes_transferred / pb_length + 1).try_into().unwrap_or(0);
    progress_bar(*curr_bars_count, 50);
}

fn basic_file_checks(path: &Path) -> io::Result<bool> {
    if path.metadata()?.len() == 0 {
        error!("File is empty");
        return Ok(false)
    }

    if path.extension().is_none() {
        warn!("No file extension.");
    }

    if path.is_dir() {
        error!("Inputted a name of a directory and not a file");
        return Err(error_other!("Not a file"))
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
    gen_encryptor: fn(&[u8]) -> T
}

impl<T> BaseSocket<T> for Sender<T>
where
    T: AeadInPlace
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
    T: AeadInPlace
{
    /// Constructs a new Sender struct, and connects to `remote_ip`.
    pub fn new(remote_ip: &str, ident: String, encryptor_func: fn(&[u8]) -> T) -> Self {
        let socket = TcpStream::connect(remote_ip).expect("Couldn't connect.");
        Sender {
            writer: SWriter(socket, EncAlgo::<T>::new(&[0u8; KEY_LENGTH], encryptor_func)),
            file_path: String::new(),
            current_pos: 0,
            identifier: ident,
            gen_encryptor: encryptor_func
        }
    }

    /// If the sender is connecting to a server (a proxy).
    ///
    /// # Errors
    /// When there is a connection error.
    fn if_server(&mut self, rece_ident: &str) -> io::Result<()> {
        // Notify the server that this sender is sending data
        self.writer.0.write(&[CLIENT_SEND])?;
        // The receiver identifier
        write_sized_buffer(&mut self.writer.0, rece_ident.as_bytes())?;
        Ok(())
    }

    fn get_starting_pos(&mut self) -> io::Result<()> {
        // Starting position from receiver
        let mut file_pos_bytes = [0u8; 8];
        debug!("Getting starting position ...");
        self.writer.read_exact(&mut file_pos_bytes)?;
        self.current_pos = u64::from_le_bytes(file_pos_bytes);
        debug!("Starting position: {}", self.current_pos);

        Ok(())
    }

    pub fn auth(&mut self, pass: &str) -> io::Result<bool> {
        let pass_encrypted = {let mut sha = Sha256::new(); sha.update(pass); sha.finalize()};

        debug!("Authenticating ...");
        self.writer.write(&pass_encrypted)?;

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
    pub fn init_send(&mut self, path: &str, receiver_identifier: Option<&str>, pass: &str) -> io::Result<bool> {
        let file_path = Path::new(path);

        if !basic_file_checks(file_path)? {
            return Ok(false)
        }

        self.file_path = path.to_string();

        let mut server_or_receiver = [0u8; 1];
        self.writer.0.read_exact(&mut server_or_receiver)?;
        if server_or_receiver[0] == SERVER {
            if let Some(ident) = receiver_identifier {
                self.if_server(ident)?;
                // Read signal
                match self.read_signal()? {
                    Signals::StartFt => (),
                    Signals::Error => {
                        error!("Receiver is not online.");
                        return Ok(false)
                    },
                    s => {
                        error!("Unexepected signal: {}", s);
                        return Ok(false);
                    }
                }
            } else {
                return Err(error_other!(errors::Errors::NoReceiverIdentifier))
            }

            // Write to the endpoint to start the transfer
            debug!("Signaling to start");
            self.signal_start()?;

            match self.read_signal()? {
                Signals::OK => (),
                Signals::Error => {error!("Receiver did not accept the request."); return Ok(false)},
                Signals::Other => {error!("Receiver blocked you."); return Ok(false)},
                _ => ()
            }

            self.shared_secret()?;
        } else {
            self.shared_secret()?;
            if !self.auth(pass)? {
                error!("Incorrect password.");
                return Ok(false)
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

        let metadata_vec_bytes = parsed.dump().as_bytes().to_vec();

        // Write metadata
        debug!("Sending metadata");
        self.writer.write(&metadata_vec_bytes)?;

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

        let mut buffer = vec![0u8; MAX_CONTENT_LEN];
        loop {
            let read_size = file.read_seek_file_sized(&mut buffer)?;
            // If we reached EOF
            if read_size == 0 {
                break;
            }
            self.current_pos += read_size as u64;

            // It's fine to include the 0's if there are any in `buffer` (only happens on the last
            // chunk of the file).
            file.update_checksum(&buffer);

            self.writer.write(&buffer)?;

            // Progress bar
            update_pb(&mut curr_bars_count, pb_length, self.current_pos);
        }

        debug!("Reached EOF");
        debug!("Writing checksum");
        buffer[..SIGNAL_LEN].copy_from_slice(Signals::EndFt.as_bytes());
        buffer[SIGNAL_LEN..MAX_CHECKSUM_LEN+SIGNAL_LEN].copy_from_slice(&file.checksum());
        self.writer.write(&buffer)?;
        info!("Finished successfully");

        Ok(())
    }
}
