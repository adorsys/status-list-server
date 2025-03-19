use jsonwebtoken::{encode, EncodingKey, Header};
use std::io::Error;

use crate::model::{StatusListToken, StatusType};

pub fn parse_token(
    token: StatusListToken,
    key: EncodingKey,
    status_type: StatusType,
) -> Result<String, Error> {
    match status_type {
        StatusType::JWT => {
            let header = Header::default();
            match encode(&header, &token, &key) {
                Ok(jwt) => Ok(jwt),
                Err(e) => {
                    tracing::error!("{}", e);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to encode jwt",
                    ))
                }
            }
        }

        StatusType::CWT => {
            // for feature implmentation
            Ok(String::new())
            // Serialize the token (claims) to CBOR bytes
            // let claims_bytes = serde_cbor::to_vec(&token).map_err(|e| {
            //     tracing::error!("CBOR serialization failed: {}", e);
            //     std::io::Error::new(std::io::ErrorKind::Other, "failed to serialize CBOR claims")
            // })?;

            // // Return the CWT as a base64 or hex string if needed
            // Ok(Base64Encoder::encode(&claims_bytes))
        }
    }
}
