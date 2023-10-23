//! Passphrase generator with high entropy.
//! This module will try to use the OS provided wordlists,
//! but if there are none, it will use BIP39 wordlist.
use crate::bip39;
use rand::{thread_rng, Rng};

pub const DELIMITER: char = '-';

/// Linux and macOS wordlist path. Windows doesn't have a native one.
const UNIX_WORDLIST: &str = "/usr/share/dict/words";

/// Generate a unique passphrase using a wordlist.
/// Generates a passphrase and not a password because its easier to remember.
pub fn generate_passphrase() -> String {
    if !["windows"].contains(&std::env::consts::OS) {
        if let Ok(content) = std::fs::read_to_string(UNIX_WORDLIST) {
            let wordlist: Vec<&str> = content.split('\n').collect();
            return random_passphrase(&wordlist);
        }
    }

    random_passphrase(&bip39::create_wordlist())
}

/// Generates a random passphrase.
fn random_passphrase(wordlist: &[&str]) -> String {
    let mut passphrase = String::new();
    let mut rng = thread_rng();
    for _ in 0..8 {
        let random_index = rng.gen_range(0..wordlist.len());
        passphrase.push_str(wordlist[random_index]);
        passphrase.push(DELIMITER);
    }

    passphrase.make_ascii_lowercase();
    passphrase
}
