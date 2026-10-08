//! Regenerate the public conformance fixture with `cargo run --example generate_test_certificate`.
//! Uses only the checked-in test key; never use this key or certificate in production.
fn main() {
    let key = rcgen::KeyPair::from_pem(include_str!("../test_data/ec-private.pem")).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into(), "example.com".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/ec-cert.pem"),
        cert.pem(),
    )
    .unwrap();
}
