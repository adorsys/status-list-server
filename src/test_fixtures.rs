//! Literal test data shared across test modules.
//!
//! Deliberately free of feature gates and dependencies — everything here is a
//! plain `&str`, so any test module can reach it whatever its own gate. That is
//! the point: [`crate::test_utils`] pulls in the memory and SQL adapters, so a
//! test module compiled without them cannot host shared data there.

/// A syntactically valid P-256 public JWK, for tests that need a key they never
/// verify anything against.
///
/// `server::auth` keeps its own copy on purpose: there it is the public half of
/// a matched keypair, and splitting the halves across modules would hide that
/// the PEM and the JWK correspond. Do not "deduplicate" the two.
///
/// Deliberately carries neither a `cfg` nor `#[allow(dead_code)]`. Both the
/// container-backed store proofs and the memory-backed handler tests use it, and
/// the latter are ungated — so it is live in every test build, and dead-code
/// analysis stays meaningful. A `cfg` narrowed to the SQL backends would break
/// `cargo test` under default features.
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
