use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read certificate from {0:?}")]
    ReadCertificate(std::path::PathBuf),
    #[error("Failed to parse certificate")]
    ParseFailed,
    #[error("provided pem file is not valid certficate")]
    PermFailed,
    #[error("invalid file type")]
    InvalidFileType,
}
