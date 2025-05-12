use jsonwebtoken::errors::Error as JwtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Missing kid in token header")]
    MissingKid,
    #[error("No issuer found for kid")]
    IssuerNotFound,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Missing Authorization header")]
    MissingAuthHeader,
    #[error("{0}")]
    JwtError(#[from] JwtError),
}
