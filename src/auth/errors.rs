use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("invalid token")]
    InvalidToken,
    #[error("missing kid in token header")]
    MissingKid,
    #[error("Repository not set")]
    RepositoryNotSet,
    #[error("No issuer found for kid")]
    IssuerNotFound,
    #[error("error: {0}")]
    Generic(String),
    #[error("Missing Authorisation header")]
    MissingAuthHeader,
    #[error("Could not verify token")]
    VerificationFailed

}
