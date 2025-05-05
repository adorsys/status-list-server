use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read certificate from {0:?}")]
    ReadCertificate(std::path::PathBuf),
    #[error("Failed to parse certificate")]
    ParseFailed,
    #[error("provided pem file is not valid certficate")]
    PermFailed,
    #[error("Failed to generate a new keypair")]
    KeyGenFailed,
    #[error("Failed to generate pem from keypair")]
    PemGenFailed,
    #[error("invalid file type")]
    InvalidFileType,
    #[error("error: {0}")]
    Generic(String),
    #[error("invalid index")]
    InvalidIndex,
    #[error("Unsupported bits value")]
    UnsupportedBits,
    #[error("Failed to decode lst")]
    DecodeError,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Failed to save new keypair {0:?}")]
    WriteCertificate(std::path::PathBuf),
    #[error("Failed to parse keypair")]
    InvalidKeyFormat,
}
