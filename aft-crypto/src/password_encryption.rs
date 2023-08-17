//! Password encryption using [`scrypt`].
pub use scrypt::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString, PasswordHash, PasswordVerifier, PasswordHashString,
    },
    Scrypt
};
pub use zeroize::Zeroize;

/// Salt size of password (not in Base64) (excludes 0)
pub const SALT_SIZE: usize = 16;
// $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt>$<hash>
// $scrypt$ln=15,r=8,p=1$<salt>$<hash>
                               // $
pub const PHC_STR_LEN: usize = 1
                               // scrypt
                               + 6
                               // $
                               + 1
                               // ln=15
                               + 5
                               // ,
                               + 1
                               // r=8
                               + 3
                               // ,
                               + 1
                               // p=1
                               + 3
                               // $
                               + 1
                               // salt
                               + 64
                               // $
                               + 1
                               // hash
                               + 64;

/// Creates a new [`scrypt`] deriven hash.
///
/// Make sure `salt` isn't Base64 encoded.
pub fn create_hash(password: &mut [u8], salt: Option<&[u8]>) -> Result<PasswordHashString, scrypt::password_hash::Error> {
    let salt = match salt {
        None => SaltString::generate(&mut OsRng),
        Some(s) => SaltString::b64_encode(s)?
    };
    let hash = Scrypt.hash_password(password, &salt)?.to_string();
    let passhash = PasswordHashString::new(&hash)?;

    password.zeroize();
    Ok(passhash)
}

pub fn verify_hash(hash: &str, password: &str) -> Result<bool, scrypt::password_hash::Error> {
    let password_hash = PasswordHash::new(hash)?;
    Ok(Scrypt.verify_password(password.as_bytes(), &password_hash).is_ok())
}
