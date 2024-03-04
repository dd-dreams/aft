use std::{error, fmt, io::Error as ioError};

#[derive(Debug)]
pub enum Errors {
    /// Represents a wrong response from the relay or the client.
    WrongResponse,
    /// Represents a wrong format buffer from the relay or the client.
    WrongFormat,
    /// Used when there is no file extension in metadata buffer.
    NoFileExtension,
    /// Stream buffer is too big.
    BufferTooBig,
    /// When requesting from a socket to download.
    NotRelay,
    /// When the client don't have the receiver's identifier.
    NoReceiverIdentifier,
    /// Invalid identifier.
    InvalidIdent,
    /// Didn't pass basic file checks.
    BasFileChcks,
    /// Invalid signal.
    InvalidSignal,
    /// Incorrect password.
    InvalidPass,
    /// Identifier unavailable.
    IdentUnaval,
    /// Input/output errors.
    IO(ioError),
}

#[derive(Debug)]
pub enum ErrorsConfig {
    WrongSyntax,
    AlreadyAssigned,
    NoOption,
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Errors::WrongResponse => write!(f, "Wrong response."),
            Errors::WrongFormat => write!(f, "Wrong format."),
            Errors::NoFileExtension => write!(f, "No file extension."),
            Errors::BufferTooBig => write!(f, "Buffer too big."),
            Errors::NotRelay => write!(f, "Not a relay."),
            Errors::NoReceiverIdentifier => write!(f, "No receiver identifier."),
            Errors::InvalidIdent => write!(f, "Invalid identifier/s."),
            Errors::BasFileChcks => write!(f, "Didn't pass basic file checks."),
            Errors::InvalidPass => write!(f, "Incorrect password."),
            Errors::IdentUnaval => write!(f, "The provided identifier is not available."),
            Errors::InvalidSignal => write!(f, "Received an invalid signal."),
            Errors::IO(err) => write!(f, "IO: {:?}", err),
        }
    }
}

impl fmt::Display for ErrorsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorsConfig::WrongSyntax => write!(f, "Bad syntax."),
            ErrorsConfig::AlreadyAssigned => write!(f, "Already assigned a value to this option."),
            ErrorsConfig::NoOption => write!(f, "No such option."),
        }
    }
}

impl From<ioError> for Errors {
    fn from(err: ioError) -> Self {
        Errors::IO(err)
    }
}

impl error::Error for Errors {}
impl error::Error for ErrorsConfig {}
