//! Very small module for exchanging keys using x25519.
use rand_core::OsRng;
pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub const KEY_LENGTH: usize = 32;

pub struct X25519Key {
    shared_secret: SharedSecret,
}

impl X25519Key {
    /// Generates a new shared secret.
    pub fn new(secret: EphemeralSecret, their_pk: &PublicKey) -> Self {
        X25519Key {
            shared_secret: X25519Key::exchange(secret, their_pk),
        }
    }

    /// Generates a secret key and a public key.
    pub fn generate_keys() -> (PublicKey, EphemeralSecret) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        (PublicKey::from(&secret), secret)
    }

    /// Combine `secret` and `pk` into a shared secret key.
    fn exchange(secret: EphemeralSecret, pk: &PublicKey) -> SharedSecret {
        secret.diffie_hellman(pk)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.shared_secret.as_bytes()
    }
}
