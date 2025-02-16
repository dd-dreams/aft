#[derive(Debug)]
pub enum EncryptionErrors {
    FailedEncrypt,
    FailedDecrypt,
    IncorrectPassword,
    InvalidLength,
}
