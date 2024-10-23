//! Handling sender.
use crate::{
    clients::{BaseSocket, Crypto, SWriter},
    constants::{
        CLIENT_SEND, CLIENT_RECV, MAX_CONTENT_LEN, MAX_METADATA_LEN, RELAY,
    },
    errors::Errors,
    utils::{
        download_speed, error_other, mut_vec, progress_bar, send_identifier, FileOperations,
        Signals
    },
};
use aft_crypto::{
    data::{AeadInPlace, EncAlgo, EncryptorBase, SData},
    exchange::{PublicKey, KEY_LENGTH},
};
use json;
use log::{debug, error, info, warn};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufReader, BufWriter, Read, Write, IoSlice},
    net::TcpStream,
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
    writer: SWriter<T, TcpStream>,
    file_path: String,
    current_pos: u64,
    gen_encryptor: fn(&[u8]) -> T,
}

impl<T> BaseSocket<T> for Sender<T>
where
    T: AeadInPlace + Sync,
{
    fn get_writer(&self) -> &SWriter<T, TcpStream> {
        &self.writer
    }

    fn get_mut_writer(&mut self) -> &mut SWriter<T, TcpStream> {
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
    T: AeadInPlace + Sync,
{
    /// Constructs a new Sender struct, and connects to `remote_ip`.
    pub fn new(remote_addr: &str, encryptor_func: fn(&[u8]) -> T) -> Self {
        let socket = TcpStream::connect(remote_addr).expect("Couldn't connect.");
        Sender {
            writer: SWriter(socket, EncAlgo::<T>::new(&[0u8; KEY_LENGTH], encryptor_func)),
            file_path: String::new(),
            current_pos: 0,
            gen_encryptor: encryptor_func,
        }
    }

    /// Signals to the endpoint to start the file transfer process.
    fn signal_start(&mut self) -> io::Result<()> {
        self.get_mut_writer().0.write_all(Signals::StartFt.as_bytes())?;
        Ok(())
    }

    /// If the sender is connecting to a relay.
    ///
    /// # Errors
    /// When there is a connection error.
    ///
    /// Returns false when the identifier is too long.
    fn if_relay(&mut self, rece_ident: &str, sen_ident: &str) -> Result<bool, Errors> {
        // Notify the relay that this client is a sender
        self.writer.0.write_all(&[CLIENT_SEND])?;

        if !(send_identifier(rece_ident.as_bytes(), &mut self.writer.0)?
            && send_identifier(sen_ident.as_bytes(), &mut self.writer.0)?)
        {
            return Err(Errors::InvalidIdent);
        }

        match self.read_signal_relay()? {
            Signals::OK => Ok(true),
            Signals::Error => Ok(false),
            _ => Err(Errors::InvalidSignal)
        }
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

    pub fn auth(&mut self, pass: SData<String>) -> io::Result<bool> {
        let pass_hashed = {
            let mut sha = Sha256::new();
            sha.update(&pass.0);
            sha.finalize()
        };

        debug!("Authenticating ...");
        self.writer.write_ext(mut_vec!(pass_hashed))?;

        Ok(self.read_signal()? == Signals::OK)
    }

    fn relay_init(&mut self, sen_ident: &str, rece_ident: Option<&str>) -> Result<bool, Errors> {
        if sen_ident.is_empty() || rece_ident.unwrap_or_default().is_empty() {
            return Err(Errors::InvalidIdent);
        }
        debug!("Connected to a relay");
        if let Some(ident) = rece_ident {
            if !self.if_relay(ident, sen_ident)? {
                error!("{ident} not online");
                return Ok(false);
            }
        } else {
            return Err(Errors::NoReceiverIdentifier);
        }

        debug!("Signaling to start");
        // Write to the endpoint to start the transfer
        self.signal_start()?;

        match self.read_signal_relay()? {
            Signals::OK => info!("Receiver accepted."),
            Signals::Error => {
                error!("Receiver rejected.");
                return Ok(false);
            }
            s => {
                error!("Received invalid signal: {}", s);
                return Err(Errors::InvalidSignal);
            }
        }

        self.shared_secret()?;

        Ok(true)
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
    ///
    /// Returns false if something went wrong (such as the identifier is too long, or when the
    /// receiver isn't online).
    pub fn init(&mut self, path: &str, sen_ident: &str, receiver_identifier: Option<&str>, pass: SData<String>) -> Result<bool, Errors> {
        let file_path = Path::new(path);

        if !basic_file_checks(file_path)? {
            return Err(Errors::BasFileChcks);
        }

        self.file_path = path.to_string();

        let mut relay_or_receiver = [0u8; 1];
        self.writer.0.read_exact(&mut relay_or_receiver)?;
        match relay_or_receiver[0] {
            RELAY => {
                if !self.relay_init(sen_ident, receiver_identifier)? {
                    return Ok(false)
                }
            },
            CLIENT_RECV => {
                self.shared_secret()?;
                if !self.auth(pass)? {
                    return Err(Errors::InvalidPass);
                }
            },
            _ => {error!("Not a relay or a receiver."); return Err(Errors::WrongResponse)}
        }

        let parsed = json::object! {
            metadata: {
                filetype: file_path.extension().unwrap_or_default().to_str().unwrap(),
                filename: file_path.file_name().unwrap().to_str().unwrap(),
                size: file_path.metadata()?.len(),
                modified: file_path.metadata()?.modified()?.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
            }
        };

        if parsed.dump().len() > MAX_METADATA_LEN {
            error!("Metadata size is too big");
            return Err(Errors::BufferTooBig);
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

    /// After the *initial connection*, we send chunks. Every chunk is data from the file.
    ///
    /// Returns error when a connection error has occurred.
    pub fn send_chunks(&mut self, num_threads: usize) -> io::Result<()> {
        let mut file = FileOperations::new(&self.file_path)?;

        if !self.check_starting_checksum(&mut file, self.current_pos)? && self.current_pos != 0  {
            error!("Checksum not equal.");
            info!("Starting from 0 since the file was modified");
            file.reset_checksum();
            self.current_pos = 0;
            file.seek_start(0)?;
        } else {
            file.seek_start(self.current_pos)?;
        }

        let file_size = file.len()?;
        let mut curr_bars_count = 0u8;
        // Add a new bar to progress bar when x bytes have been transferred
        let pb_length = file_size / 50;

        debug!("Writing chunks");
        info!("Sending file ...");
        if self.current_pos != 0 {
            update_pb(&mut curr_bars_count, pb_length, self.current_pos);
        }

        let system_time = SystemTime::now();
        let mut before = 0;
        let mut bytes_sent_sec = 0;

        // We are using a new writer because of now we use BufWriter instead of TcpStream's "slow"
        // implementation of writing.
        let mut new_writer = BufWriter::new(self.writer.0.try_clone()?);

        let mut buffer = vec![0; num_threads * MAX_CONTENT_LEN];
        let mut file_reader = BufReader::new(file.file.get_mut());

        while self.current_pos != file_size {
            let read_size = file_reader.read(&mut buffer)?;
            // If we reached EOF
            if read_size == 0 {
                break;
            }

            bytes_sent_sec += read_size;
            self.current_pos += read_size as u64;

            let encrypted_buffer: Vec<Vec<u8>> = buffer.par_chunks_exact(MAX_CONTENT_LEN).map(|chunk|
                self.writer.1.encrypt(chunk).expect("Could not encrypt")
                ).collect();
            let io_sliced_buf: Vec<IoSlice> = encrypted_buffer.iter()
                .map(|x| IoSlice::new(x)).collect();

            // TODO: Hopefully anytime soon `write_all_vectored` will be stabilized
            let _read_bytes = new_writer.write_vectored(&io_sliced_buf)?;

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

        debug!("\nReached EOF");

        debug!("Computing checksum ...");
        file.compute_checksum(u64::MAX)?;

        debug!("Ending file transfer and writing checksum");
        self.writer.write_ext(&mut file.checksum())?;

        self.writer.0.shutdown(std::net::Shutdown::Write)?;

        if self.read_signal()? == Signals::OK {
            info!("Finished successfully");
        } else {
            error!("Transfer has not completed.");
        }

        Ok(())
    }
}
