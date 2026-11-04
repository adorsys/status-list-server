//! No feature gates or dependencies, so every test module can use it.

/// server::auth keeps its own copy on purpose, paired with its private key; don't dedupe.
pub(crate) const TEST_EC_PUBLIC_JWK: &str = r#"{
    "kty": "EC",
    "crv": "P-256",
    "kid": "test-key",
    "alg": "ES256",
    "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
    "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
}"#;
