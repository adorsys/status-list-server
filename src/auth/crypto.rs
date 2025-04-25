use base64::{self, Engine};
use ring::{
    rand,
    signature::{self, UnparsedPublicKey},
};
use std::error::Error;

/// Verifies a signature using the provided public key
///
/// # Arguments
/// * `public_key_pem` - The public key in PEM format
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Result<bool, Box<dyn Error>>` - True if the signature is valid, false otherwise
pub fn verify_signature(
    public_key_pem: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Box<dyn Error>> {
    // Parse the public key from PEM format
    let public_key = parse_public_key(public_key_pem)?;

    // Create an unparsed public key for verification
    let unparsed_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);

    // Verify the signature
    match unparsed_key.verify(message, signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Parses a public key from PEM format
fn parse_public_key(pem: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // Remove PEM headers and footers
    let pem = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace('\n', "");

    // Decode from base64
    Ok(base64::engine::general_purpose::STANDARD.decode(pem)?)
}
