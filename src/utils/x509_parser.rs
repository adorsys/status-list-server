use ::pem::parse;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Loads a certificate from a PEM file and returns the DER bytes
#[inline]
pub fn load_certificate_der<P: AsRef<Path>>(cert_path: P) -> Result<Vec<u8>> {
    // Read the PEM-encoded certificate file
    let cert_pem = fs::read_to_string(&cert_path)
        .with_context(|| format!("Failed to read certificate from {:?}", cert_path.as_ref()))?;

    // Parse the PEM
    let pem = parse(cert_pem).context("Failed to parse PEM format")?;

    // Optional: Validate that it's a certificate
    if pem.tag() != "CERTIFICATE" {
        return Err(anyhow::anyhow!("Provided PEM is not a certificate"));
    }

    // Return the DER bytes
    Ok(pem.contents().to_vec())
}

mod test {

    #[test]
    fn test() {
        let cert = "./src/test_resources/test_cert.pem";
        let dec = crate::utils::x509_parser::load_certificate_der(cert).ok();
        assert!(dec.is_some())
    }
}
