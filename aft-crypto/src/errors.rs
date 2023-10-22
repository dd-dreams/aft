use std::{fmt, io};

#[derive(Debug)]
pub enum EncryptionErrors {
    FailedEncrypt,
    FailedDecrypt,
    IncorrectPassword
}

#[derive(Debug)]
pub enum CiFileErrors {
    NoSalt,
    NoNonce,
    FileStructureNotValid,
    FileDoesntExist
}

#[derive(Debug)]
pub struct CiFileError {
    kind: CiFileErrors,
}

impl Default for CiFileError {
    fn default() -> Self {
        Self { kind: CiFileErrors::FileStructureNotValid }
    }
}

impl fmt::Display for CiFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self.kind {
                CiFileErrors::NoSalt => "No salt is present.",
                CiFileErrors::NoNonce => "No nonce is present.",
                CiFileErrors::FileStructureNotValid =>
                    "File structure is wrong. Not a valid file to handle.",
                CiFileErrors::FileDoesntExist => "File doesn't exist."
            }
        )
    }
}

impl From<io::Error> for CiFileError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::UnexpectedEof => CiFileError {
                kind: CiFileErrors::FileStructureNotValid,
            },
            io::ErrorKind::NotFound => CiFileError {
                kind: CiFileErrors::FileDoesntExist,
            },
            _ => panic!("{:?}", error)
        }
    }
}
