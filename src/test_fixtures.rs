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

/// The private half of [`TEST_EC_PUBLIC_JWK`], for tests that must sign a
/// token. The pair is kept side by side so a mismatch would be visible here.
pub(crate) const TEST_EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----";
