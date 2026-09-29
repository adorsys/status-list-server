//! Documented benchmark harness for the CWT token-generation hot path.
//!
//! This exercises the production-shaped provider-to-token path end to end:
//!
//! 1. A [`CertificateProvider`] hands out an [`Arc<SigningMaterial>`] whose
//!    certificate chain was decoded **once** at construction into pre-parsed
//!    DER bytes ([`SigningMaterial::certificate_der`]). The provider returns an
//!    `Arc`, so a per-request call is a cheap `Arc` clone rather than a deep
//!    clone of the chain.
//! 2. The per-iteration loop builds the CWT `x5chain` protected header from
//!    that pre-decoded DER and signs a status-list CWT — mirroring the
//!    `build_status_list_token` / `issue_cwt` flow in
//!    `src/server/handlers/status_list/utils/token.rs` without an HTTP stack.
//!
//! It uses a representative multi-certificate chain (leaf + intermediate +
//! root), as production issuers carry more than a single certificate.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --example cwt_bench [iterations]
//! ```
//!
//! Defaults to 100_000 iterations. It reports per-token latency (µs) and
//! throughput (tokens/sec). These are informational measurements for
//! comparing this branch against a before/after baseline; they are not an
//! absolute CI threshold.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use coset::{
    CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
    cbor::Value as CborValue,
    iana::{Algorithm, EnumI64, HeaderParameter},
};
use status_list_server::crypto::SigningKey;
use status_list_server::domain::models::status_list::{
    StatusList, StatusListError, StatusListRecord,
};
use status_list_server::domain::models::token::SigningAlgorithm;
use status_list_server::domain::ports::{CertificateProvider, SigningMaterial, TokenSigner};

// CWT label/type constants, kept in sync with
// `src/server/handlers/status_list/utils/constants.rs`.
const CWT_TYPE: i64 = 16;
const SUBJECT: i32 = 2;
const ISSUED_AT: i32 = 6;
const EXP: i32 = 4;
const TTL: i32 = 65534;
const STATUS_LIST: i32 = 65533;
const CWT_TYPE_VALUE: &str = "application/statuslist+cwt";

/// A provider that returns an `Arc<SigningMaterial>` built once from a
/// representative multi-certificate chain, exactly as the real adapters do.
struct BenchProvider {
    material: Arc<SigningMaterial>,
}

#[async_trait]
impl CertificateProvider for BenchProvider {
    async fn signing_material(&self) -> Result<Arc<SigningMaterial>, StatusListError> {
        Ok(self.material.clone())
    }
}

fn representative_chain() -> Vec<String> {
    // Fake DER payloads for a leaf, intermediate, and root. Only the encoding
    // path is exercised here, so the bytes need not be parseable X.509; they
    // must merely be valid base64 (as a real chain's DER would be).
    ["leaf-der", "intermediate-der", "root-der"]
        .iter()
        .map(|d| BASE64_STANDARD.encode(d.as_bytes()))
        .collect()
}

fn sample_record() -> StatusListRecord {
    StatusListRecord {
        list_id: "list-1".into(),
        issuer: "test-issuer".into(),
        sub: "https://example.com/status-list/1".into(),
        status_list: StatusList {
            bits: 1,
            lst: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"\x00\x01\x02\x03"),
        },
        updated_at: 1000,
    }
}

fn x5chain_from_der(certs: &[Box<[u8]>]) -> CborValue {
    if certs.len() == 1 {
        CborValue::Bytes(certs[0].to_vec())
    } else {
        CborValue::Array(
            certs
                .iter()
                .map(|der| CborValue::Bytes(der.to_vec()))
                .collect(),
        )
    }
}

fn cose_algorithm(algorithm: SigningAlgorithm) -> Algorithm {
    Algorithm::from_i64(algorithm.cose_id()).expect("supported COSE algorithm")
}

struct CwtClaims<'a> {
    sub: &'a str,
    bits: u8,
    lst_bytes: &'a [u8],
    iat: i64,
    exp: i64,
    token_ttl_secs: u64,
}

fn issue_cwt(
    params: &CwtClaims<'_>,
    signer: &(impl TokenSigner + ?Sized),
    x5chain: CborValue,
) -> Vec<u8> {
    let mut claims = vec![
        (
            CborValue::Integer(SUBJECT.into()),
            CborValue::Text(params.sub.into()),
        ),
        (
            CborValue::Integer(ISSUED_AT.into()),
            CborValue::Integer(params.iat.into()),
        ),
        (
            CborValue::Integer(EXP.into()),
            CborValue::Integer(params.exp.into()),
        ),
        (
            CborValue::Integer(TTL.into()),
            CborValue::Integer(params.token_ttl_secs.into()),
        ),
    ];

    let status_list = vec![
        (
            CborValue::Text("bits".into()),
            CborValue::Integer(params.bits.into()),
        ),
        (
            CborValue::Text("lst".into()),
            CborValue::Bytes(params.lst_bytes.to_vec()),
        ),
    ];
    claims.push((
        CborValue::Integer(STATUS_LIST.into()),
        CborValue::Map(status_list),
    ));

    let payload = CborValue::Map(claims).to_vec().expect("encode payload");

    let protected = HeaderBuilder::new()
        .algorithm(cose_algorithm(signer.algorithm()))
        .value(HeaderParameter::X5Chain.to_i64(), x5chain)
        .value(CWT_TYPE, CborValue::Text(CWT_TYPE_VALUE.into()))
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .try_create_signature(&[], |tbs| signer.sign(tbs))
        .expect("create signature")
        .build();

    sign1.to_tagged_vec().expect("encode CWT")
}

#[tokio::main]
async fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100_000);

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let signing_key = Arc::new(SigningKey::generate(SigningAlgorithm::Es256).expect("key"));
    let material = Arc::new(
        SigningMaterial::new(Some(representative_chain()), signing_key).expect("material"),
    );
    let provider = BenchProvider {
        material: material.clone(),
    };
    let record = sample_record();
    let lst_bytes = b"\x00\x01\x02\x03".to_vec();
    let claims = CwtClaims {
        sub: &record.sub,
        bits: record.status_list.bits,
        lst_bytes: &lst_bytes,
        iat: 1_000,
        exp: 2_000,
        token_ttl_secs: 300,
    };

    // Warm up once so the provider/telemetry path is stable.
    let material = provider.signing_material().await.expect("material");
    let x5chain = x5chain_from_der(material.certificate_der().expect("der chain"));
    issue_cwt(&claims, material.signing_key.as_ref(), x5chain);

    let start = Instant::now();
    for _ in 0..iterations {
        let material = provider.signing_material().await.expect("material");
        let x5chain = x5chain_from_der(material.certificate_der().expect("der chain"));
        issue_cwt(&claims, material.signing_key.as_ref(), x5chain);
    }
    let elapsed = start.elapsed();

    let per_token_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let per_token_us = per_token_ns / 1_000.0;
    let throughput = iterations as f64 / elapsed.as_secs_f64();

    println!("CWT provider-to-token benchmark (Es256, 3-cert chain):");
    println!("  iterations      : {iterations}");
    println!("  total           : {elapsed:?}");
    println!("  latency         : {per_token_us:.3} µs/token ({per_token_ns:.1} ns/token)");
    println!("  throughput      : {throughput:.0} tokens/sec");
}
