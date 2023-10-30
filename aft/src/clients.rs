//! Clients (Receiver and Downloader).
use crate::{
    constants::{
        BLOCKED_FILENAME, CLIENT_RECV, MAX_CHECKSUM_LEN, MAX_CONTENT_LEN, MAX_IDENTIFIER_LEN,
        MAX_METADATA_LEN, RELAY, SHA_256_LEN, SIGNAL_LEN,
    },
    utils::{bytes_to_string, get_accept_input, mut_vec, send_identifier, FileOperations, Signals},
};
use aft_crypto::{
    data::{AeadInPlace, EncAlgo, EncryptorBase, SData, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE},
    exchange::{PublicKey, X25519Key, KEY_LENGTH},
};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};

/// Opens a file.
///
/// Returns the file object, and boolean saying if it was newly created or opened.
/// Error when there was an error creating or opening a file.
fn checks_open_file(metadata: &json::JsonValue) -> io::Result<(FileOperations, bool)> {
    // Removing "/" at the start, to avoid unwanted behavior. There should be a warning about it at
    // the sender's side.
    let filename_trimmed = metadata["metadata"]["filename"].as_str().unwrap_or("null").trim_start_matches('/');
    // (filename is not a path).
    let filename = &format!(r"./.{}.tmp", filename_trimmed);

    if FileOperations::is_file_exists(filename) {
        let mut file = FileOperations::new(filename)?;
        // New data is added at the end
        file.seek_end(0)?;
        Ok((file, true))
    } else {
        let file = FileOperations::new_create(filename)?;
        Ok((file, false))
    }
}

/// A safe writer. Acts like a normal writer only that it encrypts the connection.
pub struct SWriter<T>(pub TcpStream, pub EncAlgo<T>);

struct UserBlocks {
    file: FileOperations,
}

impl<T> Write for SWriter<T>
where
    T: AeadInPlace,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let enc_buf = self.1.encrypt(buf).expect("Could not encrypt.");
        Ok(self.0.write(&enc_buf)? - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<T> Read for SWriter<T>
where
    T: AeadInPlace,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = vec![0; buf.len() + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE];
        let bytes_read = self.0.read(&mut read_buf)?;

        if bytes_read < AES_GCM_NONCE_SIZE {
            return Ok(0);
        }

        read_buf.truncate(bytes_read);

        let (data, nonce) = read_buf.split_at(read_buf.len() - AES_GCM_NONCE_SIZE);
        let dec_buf = self.1.decrypt(data, nonce).expect("Could not decrypt.");
        buf[..dec_buf.len()].copy_from_slice(&dec_buf);

        Ok(bytes_read - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE)
    }
}

impl<T> SWriter<T>
where
    T: AeadInPlace,
{
    /// Better implementation of `write`. Instead of creating a new buffer to encrypt to, it writes
    /// and encrypts "in place".
    ///
    /// Use this method for better efficiency.
    pub fn write_ext(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        // Automatically adds the tag and the nonce.
        self.1.encrypt_in_place(buf).expect("Could not encrypt.");
        self.0.write_all(buf)?;

        buf.truncate(buf.len() - AES_GCM_TAG_SIZE - AES_GCM_NONCE_SIZE);
        Ok(())
    }

    /// Better implementation of `read`. Instead of creating a new buffer to read to, it reads "in
    /// place".
    ///
    /// Use this method for better efficiency.
    pub fn read_ext(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.extend_from_slice(&[0; AES_GCM_TAG_SIZE]);
        // Reading the encrypted chunk
        self.0.read_exact(buf)?;
        let mut nonce = [0; AES_GCM_NONCE_SIZE];
        // Reading the nonce
        self.0.read_exact(&mut nonce)?;

        // This method automatically removes the tag
        self.1.decrypt_in_place(buf, &nonce).expect("Could not decrypt.");

        Ok(())
    }
}

impl UserBlocks {
    /// Constructor.
    pub fn new(path: &str) -> io::Result<Self> {
        Ok(UserBlocks {
            file: FileOperations::new(path)?,
        })
    }

    /// Checks if an IP is blocked.
    pub fn check_block(&mut self, ip: &str) -> io::Result<bool> {
        let mut content = Vec::new();
        self.file.seek_start(0)?;
        self.file.file.read_to_end(&mut content)?;

        let ip_bytes = ip.as_bytes();

        // Split at newline
        for line in content.split(|i| i == &10u8) {
            if line == ip_bytes {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn add_block(&mut self, ip: &str) -> io::Result<()> {
        self.file.write(format!("{}\n", ip).as_bytes())?;
        Ok(())
    }
}

pub trait BaseSocket<T>
where
    T: AeadInPlace,
{
    /// Returns the writer used in the connection.
    fn get_writer(&self) -> &SWriter<T>;

    /// Returns a mutable writer used in the connection.
    fn get_mut_writer(&mut self) -> &mut SWriter<T>;

    /// Reads a signal from the endpoint.
    ///
    /// Returns the signal.
    fn read_signal(&mut self) -> io::Result<Signals> {
        let mut signal = vec![0u8; SIGNAL_LEN];
        self.get_mut_writer().read_ext(&mut signal)?;
        let signal = bytes_to_string(&signal);
        Ok(signal.as_str().into())
    }

    /// Reads a signal from a relay.
    ///
    /// Returns the signal.
    fn read_signal_relay(&mut self) -> io::Result<Signals> {
        let mut signal = vec![0u8; SIGNAL_LEN];
        self.get_mut_writer().0.read_exact(&mut signal)?;
        let signal = bytes_to_string(&signal);

        Ok(signal.as_str().into())
    }

    /// Reads the metadata.
    ///
    /// Returns a JSON object of the metadata.
    fn read_metadata(&mut self) -> io::Result<json::JsonValue> {
        let mut metadata = vec![0; MAX_METADATA_LEN];
        self.get_mut_writer().read_ext(&mut metadata)?;

        let metadata_json = json::parse(&{
            let metadata_string = bytes_to_string(&metadata);
            // Reading the metadata is a fixed size, and len(metadata) <= MAX_METADATA_LEN, so we
            // need to split `metadata`.
            match metadata_string.split_once('\0') {
                None => metadata_string,
                Some(v) => v.0.to_string(),
            }
        }).expect("Couldn't convert metadata buffer to JSON.");
        log::trace!("{}", metadata_json.pretty(2));

        Ok(metadata_json)
    }

    /// Reads chunks of the file from the endpoint and writes them into a file object.
    ///
    /// Returns the file-checksum of the sender's.
    fn read_write_data(&mut self, file: &mut FileOperations, supposed_len: u64) -> io::Result<Vec::<u8>> {
        let mut content = vec![0; MAX_CONTENT_LEN];

        info!("Reading file chunks ...");
        loop {
            self.get_mut_writer().read_ext(&mut content)?;
            if &content[..SIGNAL_LEN] == Signals::EndFt.as_bytes() {
                file.file.set_len(supposed_len)?;
                break;
            }

            file.update_checksum(&content);
            file.write(&content)?;
        }

        // Returns the sender's checksum
        Ok(content[SIGNAL_LEN..MAX_CHECKSUM_LEN + SIGNAL_LEN].to_vec())
    }

    /// Returns true if checksums are equal, false if they're not.
    ///
    /// Returns error when there is a connection error.
    fn check_checksum(&mut self, checksum: &[u8], file_checksum: &[u8]) -> bool {
        debug!("Checking checksum");
        if checksum != file_checksum {
            error!("Checksum not equal");
            false
        } else {
            debug!("Checksum equal");
            true
        }
    }

    /// Gets shared secret from both endpoints and creates a new "encryptor" object to encrypt the
    /// connection.
    fn shared_secret(&mut self) -> io::Result<()>;

    /// The main function for downloading in a P2P mode (sender -> receiver) or from a relay.
    fn download(&mut self) -> io::Result<bool> {
        info!("Waiting ...");

        debug!("Getting metadata");
        let metadata = self.read_metadata()?;

        let sizeb = metadata["metadata"]["size"].as_u64().unwrap_or(0);
        let sizemb = sizeb / 10_u64.pow(6);
        info!("Incoming {}MB from {}!", sizemb, metadata["sender"]["identifier"]);

        let (mut file, existed) = checks_open_file(&metadata)?;

        // TODO: Add metadata checks, such as checking if there is enough space.

        if existed && file.len()? != sizeb {
            self.get_mut_writer().write_ext(mut_vec!((file.len()?).to_le_bytes()))?;
        } else {
            self.get_mut_writer().write_ext(mut_vec!([0u8; 8]))?;
        }

        // TODO: Receive the current computed checksum based on the file position

        let filename = metadata["metadata"]["filename"].as_str().unwrap_or("null");

        let recv_checksum = self.read_write_data(&mut file, sizeb)?;
        // If the checksum isn't good
        if !self.check_checksum(&recv_checksum, &file.checksum())
            && get_accept_input("Keep the file? ").expect("Couldn't read answer") != 'y' {
            FileOperations::rm(&format!(".{}.tmp", filename))?;
            return Ok(false);
        }

        FileOperations::rename(&format!(".{}.tmp", filename), filename)?;
        Ok(true)
    }
}

pub trait Crypto {
    /// Exchanges the public key between two parties.
    ///
    /// Returns the other party public key.
    fn exchange_pk(&mut self, pk: PublicKey) -> io::Result<PublicKey>;

    /// Generates a public key and a secret key and finally a shared secret.
    ///
    /// Returns a shared secret.
    fn gen_shared_secret(&mut self) -> io::Result<X25519Key> {
        info!("Exchanging keys");
        let (pk, secret) = X25519Key::generate_keys();

        Ok(X25519Key::new(secret, &self.exchange_pk(pk)?))
    }
}

pub struct Downloader<T> {
    writer: SWriter<T>,
    ident: String,
    gen_encryptor: fn(&[u8]) -> T,
    blocks: UserBlocks,
}

impl<T> BaseSocket<T> for Downloader<T>
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

impl<T> Crypto for Downloader<T>
where
    T: AeadInPlace,
{
    fn exchange_pk(&mut self, pk: PublicKey) -> io::Result<PublicKey> {
        let mut other_pk = [0; 32];

        // Writing the public key
        debug!("Writing public key");
        self.writer.0.write_all(pk.as_bytes())?;
        // Getting endpoint's public key
        debug!("Getting public key");
        self.writer.0.read_exact(&mut other_pk)?;

        Ok(PublicKey::from(other_pk))
    }
}

impl<T> Downloader<T>
where
    T: AeadInPlace,
{
    /// Constructor. Connects to `remote_ip` automatically.
    pub fn new(remote_ip: &str, ident: String, encryptor_func: fn(&[u8]) -> T) -> Self {
        let socket = TcpStream::connect(remote_ip).expect("Couldn't connect.");
        Downloader { ident,
            writer: SWriter(socket, EncAlgo::<T>::new(&[0u8; KEY_LENGTH], encryptor_func)),
            gen_encryptor: encryptor_func,
            blocks: UserBlocks::new(BLOCKED_FILENAME).expect("Couldn't open blocked users file."),
        }
    }

    /// Checks if the receiver is connected to a relay.
    ///
    /// Returns true if yes, and false if not.
    pub fn is_connected_to_relay(&mut self) -> io::Result<bool> {
        let mut relay_or_client = [0u8; 1];
        self.writer.0.read_exact(&mut relay_or_client)?;
        Ok(relay_or_client[0] == RELAY)
    }

    /// The main method when connecting to a relay. Handles the transferring process.
    pub fn init(&mut self) -> io::Result<bool> {
        if !self.is_connected_to_relay()? {
            error!("Not a relay");
            return Ok(false);
        }

        // Write to the relay the client connecting is a receiver
        self.writer.0.write_all(&[CLIENT_RECV])?;

        if !send_identifier(self.ident.as_bytes(), &mut self.writer.0)? {
            return Ok(false);
        }

        info!("Waiting for requests ...");
        loop {

            loop {
                match self.read_signal_relay()? {
                    Signals::StartFt => break,
                    // Connectivity check
                    Signals::Other => self.writer.0.write_all(&[1])?,
                    Signals::Error => {
                        info!("This identifier is not available.");
                        return Ok(false);
                    }
                    s => panic!("Invalid signal when reading signal from relay. {}", s),
                }
            }

            // Read the sender's identifier
            let mut sen_ident_bytes = [0; MAX_IDENTIFIER_LEN];
            self.writer.0.read_exact(&mut sen_ident_bytes)?;
            let sen_ident = &bytes_to_string(&sen_ident_bytes);

            // Read the sender's hashed IP
            let mut sen_hashed_ip_bytes = [0; SHA_256_LEN];
            self.writer.0.read_exact(&mut sen_hashed_ip_bytes)?;
            let sen_hashed_ip = &bytes_to_string(&sen_hashed_ip_bytes);

            // If this IP isn't blocked
            if !self.blocks.check_block(sen_hashed_ip)? {
                match get_accept_input(&format!("{} wants to send you a file (y/n/b): ", sen_ident))? {
                    // Yes
                    'y' => break,
                    // No
                    'n' => (),
                    // Block
                    'b' => self.blocks.add_block(sen_hashed_ip)?,
                    // Invalid input
                    _ => panic!("Invalid input"),
                };
            }

            // If the receiver rejected/blocked him
            self.writer.0.write_all(Signals::Error.as_bytes())?;
        }

        // Write that the receiver accepts the request
        self.writer.0.write_all(Signals::OK.as_bytes())?;

        // Exchange secret key with the sender
        self.shared_secret()?;

        if !self.download()? {
            return Ok(false);
        }

        info!("Finished successfully");
        Ok(true)
    }
}

pub struct Receiver<T> {
    writer: SWriter<T>,
    gen_encryptor: fn(&[u8]) -> T,
}

impl<T> BaseSocket<T> for Receiver<T>
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

impl<T> Crypto for Receiver<T>
where
    T: AeadInPlace,
{
    fn exchange_pk(&mut self, pk: PublicKey) -> io::Result<PublicKey> {
        let mut other_pk = [0; 32];

        // Writing the public key
        debug!("Writing public key");
        self.writer.0.write_all(pk.as_bytes())?;
        // Getting endpoint's public key
        debug!("Getting public key");
        self.writer.0.read_exact(&mut other_pk)?;

        Ok(PublicKey::from(other_pk))
    }
}

impl<T> Receiver<T>
where
    T: AeadInPlace,
{
    /// Constructor. Creates a listener on `addr` automatically.
    pub fn new(addr: &str, encryptor_func: fn(&[u8]) -> T) -> Self {
        let listener = TcpListener::bind(addr).expect("Couldn't bind to address");
        let (socket, _) = listener.accept().expect("Couldn't accept connection");
        info!("Connected to sender");

        Receiver {
            writer: SWriter(socket, EncAlgo::<T>::new(&[0u8; KEY_LENGTH], encryptor_func)),
            gen_encryptor: encryptor_func
        }
    }

    /// Authenticates with the sender's end.
    ///
    /// Returns true if the password received from the sender is the correct password, else false.
    pub fn auth(&mut self, correct_pass: &str) -> io::Result<bool> {
        info!("Authenticating ...");

        // Sha256 is 256 bits => 256 / 8 => 32
        let mut pass = SData(vec![0; 32]);
        self.writer.read_ext(&mut pass.0)?;

        let mut sha = Sha256::new();
        sha.update(correct_pass);

        if pass.0 == sha.finalize().as_slice() {
            self.writer.write_ext(mut_vec!(Signals::OK.as_bytes()))?;
            Ok(true)
        } else {
            self.writer.write_ext(mut_vec!(Signals::Error.as_bytes()))?;
            Ok(false)
        }
    }

    /// The main function for receiving in P2P mode (sender -> receiver).
    pub fn receive(&mut self, pass: SData<String>) -> io::Result<bool> {
        // Write to the sender that its connecting to a receiver
        self.writer.0.write_all(&[CLIENT_RECV])?;

        self.shared_secret()?;

        if !self.auth(&pass.0)? {
            error!("Received bad password");
            return Ok(false);
        }

        if !self.download()? {
            return Ok(false);
        }

        info!("Finished successfully");
        Ok(true)
    }
}
