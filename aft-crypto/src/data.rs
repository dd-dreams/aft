//! Data encryption with AEAD (Authenticated encryption).
pub use aes_gcm::{
    aead::{generic_array::GenericArray, rand_core::RngCore, AeadInPlace, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Nonce, Tag, TagSize
};
use crate::exchange::KEY_LENGTH;
use crate::errors::EncryptionErrors;
use zeroize::Zeroize;

pub type Result<T> = core::result::Result<T, EncryptionErrors>;
pub type AesGcm128Enc = EncAlgo<Aes128Gcm>;
pub type AesGcm256Enc = EncAlgo<Aes256Gcm>;

/// Nonce size (in bytes) of AES-GCM (excludes 0)
pub const AES_GCM_NONCE_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Algo {
    Aes128,
    Aes256,
    Unknown,
}

impl From<&str> for Algo {
    fn from(v: &str) -> Self {
        match v {
            "aes128" => Algo::Aes128,
            "aes256" => Algo::Aes256,
            _ => Algo::Unknown
        }
    }
}

impl From<&Algo> for &str {
    fn from(v: &Algo) -> Self {
        match v {
            Algo::Aes128 => "aes128",
            Algo::Aes256 => "aes256",
            Algo::Unknown => "unknown"
        }
    }
}


// Creates a new AES-GCM encryptor.
macro_rules! create_aes_gcm_encryptor {
    ($key:expr, $aesgcm:ident) => {{
        let arr_key = GenericArray::from_slice($key);
        $aesgcm::new(arr_key)
    }};
}

#[macro_export]
/// Quickly decrypt AES-GCM data.
macro_rules! decrypt_aes_gcm {
    ($encryptor:expr, $data:expr) => {
        $encryptor.decrypt(
            &$data[..$data.len()-AES_GCM_NONCE_SIZE], &$data[$data.len()-AES_GCM_NONCE_SIZE..])
            .expect("Could not decrypt")
    }
} pub use decrypt_aes_gcm;

pub trait EncryptorBase<CiAlgo>
where
    CiAlgo: AeadInPlace,
{
    /// Encrypt data without changing the original data.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encrypted_data = data.to_vec();
        self.encrypt_in_place(&mut encrypted_data)?;

        Ok(encrypted_data)
    }

    /// Decrypt data without changing the original data.
    fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let mut decrypted_data = data.to_vec();
        self.decrypt_in_place(&mut decrypted_data, nonce)?;

        Ok(decrypted_data)
    }

    /// Encrypt data in-place.
    fn encrypt_in_place(&self, data: &mut Vec<u8>) -> Result<()> {
        // The nonce is 12 bytes (96 bits) long.
        // According to NIST 38D, 12 bytes should be used for efficiency and simplicity.
        let mut nonce = vec![0; AES_GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // Note: authentication tag is appended to the encrypted data.
        if self.get_encryptor().encrypt_in_place(Nonce::from_slice(&nonce), b"", data).is_err() {
            return Err(EncryptionErrors::FailedEncrypt);
        }

        // Adding nonce to data
        data.append(&mut nonce);

        Ok(())
    }

    /// Decrypt data in-place.
    fn decrypt_in_place(&self, data: &mut Vec<u8>, nonce: &[u8]) -> Result<()> {
        let nonce = Nonce::from_slice(nonce);
        if self.get_encryptor().decrypt_in_place(nonce, b"", data).is_err() {
            return Err(EncryptionErrors::FailedDecrypt);
        }

        Ok(())
    }

    fn decrypt_in_place_detached(&self, data: &mut [u8], nonce: &[u8]) -> Result<()> {
        if data.len() < AES_GCM_TAG_SIZE {
            return Err(EncryptionErrors::InvalidLength);
        }

        let tag_pos = data.len() - AES_GCM_TAG_SIZE;
        let (d, tag) = data.as_mut().split_at_mut(tag_pos);
        // TODO: remove expect
        self.get_encryptor().
            decrypt_in_place_detached(nonce.into(), b"", d, Tag::from_slice(tag)).expect("FailedDecrypting");

        Ok(())
    }

    fn get_encryptor(&self) -> &CiAlgo;
}

/// Struct to represent an object to encrypt data with some encryption algorithm.
pub struct EncAlgo<T> {
    key: [u8; KEY_LENGTH],
    encryptor_func: fn(&[u8]) -> T,
    encryptor: T,
}

impl<T> EncAlgo<T> {
    pub fn new(key: &[u8; KEY_LENGTH], encryptor_func: fn(&[u8]) -> T) -> Self {
        Self {
            key: *key,
            encryptor_func,
            encryptor: encryptor_func(key),
        }
    }
}

impl<T> Clone for EncAlgo<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            encryptor_func: self.encryptor_func,
            encryptor: (self.encryptor_func)(&self.key),
        }
    }
}

/// Creates a new AES-GCM-128 encryptor.
/// [`key`] must be at least 16 bytes long.
pub fn create_128_encryptor(key: &[u8]) -> Aes128Gcm {
    // AES-128 uses 16 bytes keys
    create_aes_gcm_encryptor!(&key[..16], Aes128Gcm)
}

/// Creates a new AES-GCM-256 encryptor.
/// [`key`] must be at least 32 bytes long.
pub fn create_256_encryptor(key: &[u8]) -> Aes256Gcm {
    // AES-256 uses 32 bytes keys
    create_aes_gcm_encryptor!(&key[..32], Aes256Gcm)
}

impl<CiAlgo> EncryptorBase<CiAlgo> for EncAlgo<CiAlgo>
where
    CiAlgo: AeadInPlace,
{
    fn get_encryptor(&self) -> &CiAlgo {
        &self.encryptor
    }
}

/// Safe Data. Zeros when dropped.
pub struct SData<T: Zeroize>(pub T);

impl<T: Zeroize> Drop for SData<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
