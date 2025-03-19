use std::{env, fs, path::Path};

use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::DecodePrivateKey, rand_core::OsRng, RsaPrivateKey};

#[inline]
pub fn get_or_generate_private_key() -> Result<RsaPrivateKey, std::io::Error> {
    let path_str =
        env::var("KEY_STORAGE").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new(&path_str);

    if path.exists() && path.metadata()?.len() > 0 {
        tracing::info!("Loading existing private key...");
        let pem = fs::read_to_string(path)?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(private_key)
    } else {
        tracing::info!("Generating new RSA key pair...");
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
            .to_string();
        fs::write(path, pem)?;
        tracing::info!("Private key saved.");
        Ok(private_key)
    }
}
