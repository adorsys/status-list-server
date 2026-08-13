#[cfg(feature = "aws-s3")]
mod s3;
#[cfg(feature = "aws-s3")]
pub use s3::AwsS3;

#[cfg(feature = "aws-secrets")]
mod secrets;
#[cfg(feature = "aws-secrets")]
pub use secrets::AwsSecretsManager;
