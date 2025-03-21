use ::pem::parse;
use std::fs;
use std::path::Path;

use super::errors::Error;

/// Loads a certificate from a PEM file and returns the DER bytes
#[inline]
pub fn load_certificate_der<P: AsRef<Path>>(cert_path: P) -> Result<Vec<u8>, Error> {
    let path = cert_path.as_ref();

    // Check file extension is .pem
    if path.extension().and_then(|s| s.to_str()).unwrap_or("") != "pem" {
        Err(Error::InvalidFileType)?;
    }

    // Read the PEM-encoded certificate file
    let cert_pem =
        fs::read_to_string(path).map_err(|_| Error::ReadCertificate(path.to_path_buf()))?;

    // Parse the PEM
    let pem = parse(cert_pem).map_err(|_| Error::ParseFailed)?;

    // Optional: Validate that it's a certificate
    if pem.tag() != "CERTIFICATE" {
        return Err(Error::PermFailed);
    }

    // Return the DER bytes
    Ok(pem.contents().to_vec())
}

mod test {

    #[test]
    fn test_certificates() {
        let test_certs = vec![
            "./src/test_resources/test_cert.pem",
            "./src/test_resources/test_cert2.pem",
        ];

        for cert_path in test_certs {
            let dec = crate::utils::x509_parser::load_certificate_der(cert_path).ok();
            assert!(dec.is_some(), "Failed to parse {}", cert_path);
        }
    }
    #[test]
    fn test_der_encoded_certificate_content() {
        // Pretend this is DER content (binary-like junk data in a .pem)
        let test_cert = "./src/test_resources/test_cert.der";
        let res = crate::utils::x509_parser::load_certificate_der(test_cert).ok();
        assert!(res.is_none());
    }
}
