#![cfg(feature = "memory")]

//! Draft-21 wire assertions: literal labels deliberately do not share issuer constants.
use std::io::Read;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use base64::{
    Engine as _,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use coset::{CborSerializable, TaggedCborSerializable, cbor::Value};
use reqwest::{Response, StatusCode};
use serde_json::json;
mod utils;
use utils::{TestServer, certificate};

async fn publish(app: &TestServer) -> String {
    let list_id = uuid::Uuid::new_v4();
    let response = app
        .client
        .put(app.url(&format!("/api/v1/status-lists/{list_id}/statuses")))
        .bearer_auth(app.bearer_token())
        .json(&json!({"statuses": [{"index": 0, "status": 1}, {"index": 15, "status": 0}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["uri"], location);
    let expected = app.url(&format!("/api/v1/status-lists/{list_id}"));
    assert_eq!(
        location, expected,
        "publish must build the URI from the configured bound address"
    );
    location
}

async fn get(app: &TestServer, uri: &str, accept: &str, encoding: &str) -> Response {
    app.client
        .get(app.url(uri))
        .header("accept", accept)
        .header("accept-encoding", encoding)
        .header("origin", "https://verifier.example")
        .send()
        .await
        .unwrap()
}

async fn bytes(response: Response) -> Vec<u8> {
    response.bytes().await.unwrap().to_vec()
}

fn certificate_key(der: &[u8]) -> Vec<u8> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty());
    cert.public_key().subject_public_key.data.to_vec()
}

fn verified_jwt(body: &[u8]) -> serde_json::Value {
    let token = std::str::from_utf8(body).unwrap();
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("statuslist+jwt"));
    assert_eq!(
        header.x5c.as_ref().unwrap(),
        &[BASE64_STANDARD.encode(pem::parse(certificate()).unwrap().contents())]
    );
    let der = BASE64_STANDARD.decode(&header.x5c.unwrap()[0]).unwrap();
    let key = jsonwebtoken::DecodingKey::from_ec_der(&certificate_key(&der));
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    // Verify the signature independently of wall-clock time; check claim ordering below.
    validation.validate_exp = false;
    let claims: serde_json::Value = jsonwebtoken::decode(token, &key, &validation)
        .unwrap()
        .claims;
    assert!(claims["iat"].as_i64().unwrap() < claims["exp"].as_i64().unwrap());
    claims
}

fn field(map: &Value, key: Value) -> &Value {
    let entries = map
        .as_map()
        .expect("CBOR map, without an enclosing CWT tag");
    assert_eq!(entries.iter().filter(|(k, _)| k == &key).count(), 1);
    &entries.iter().find(|(k, _)| k == &key).unwrap().1
}

fn unsigned(value: &Value) -> u64 {
    u64::try_from(value.as_integer().expect("unsigned integer")).unwrap()
}

fn assert_list(compressed: &[u8]) {
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(raw, [1, 0]);
}

#[tokio::test]
async fn jwt_get_conforms_with_and_without_aggregation_uri() {
    for aggregation_uri in [
        None,
        Some(String::new()),
        Some("   ".to_owned()),
        Some("https://example.com/api/v1/aggregation".to_owned()),
    ] {
        let app = TestServer::start(aggregation_uri.clone()).await;
        let aggregation_uri = aggregation_uri
            .filter(|value| !value.trim().is_empty())
            .map(|base| format!("{base}/{}", app.aggregation_id));
        let uri = publish(&app).await;
        let response = get(&app, &uri, "application/statuslist+jwt", "identity").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/statuslist+jwt"
        );
        assert!(!response.headers().contains_key("content-encoding"));
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let claims = verified_jwt(&bytes(response).await);
        assert_eq!(claims["sub"], uri);
        assert!(claims["ttl"].as_u64().unwrap() > 0);
        assert!([1, 2, 4, 8].contains(&claims["status_list"]["bits"].as_u64().unwrap()));
        let lst = claims["status_list"]["lst"].as_str().unwrap();
        assert!(
            lst.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_list(&BASE64_URL_SAFE_NO_PAD.decode(lst).unwrap());
        assert_eq!(
            claims["status_list"].get("aggregation_uri"),
            aggregation_uri.as_ref().map(|uri| json!(uri)).as_ref()
        );
    }
}

#[tokio::test]
async fn cwt_get_conforms_with_and_without_aggregation_uri() {
    for aggregation_uri in [
        None,
        Some(String::new()),
        Some("   ".to_owned()),
        Some("https://example.com/api/v1/aggregation".to_owned()),
    ] {
        let app = TestServer::start(aggregation_uri.clone()).await;
        let aggregation_uri = aggregation_uri
            .filter(|value| !value.trim().is_empty())
            .map(|base| format!("{base}/{}", app.aggregation_id));
        let uri = publish(&app).await;
        for encoding in ["identity", "gzip", "gzip, deflate, br, zstd", "*"] {
            let response = get(&app, &uri, "application/statuslist+cwt", encoding).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "application/statuslist+cwt"
            );
            assert!(!response.headers().contains_key("content-encoding"));
            let body = bytes(response).await;
            assert_eq!(body[0], 0xd2);
            // Decoding a tagged Sign1 and then a bare claims map rejects tag 61 at either level.
            let sign1 = coset::CoseSign1::from_tagged_slice(&body).unwrap();
            let protected =
                Value::from_slice(sign1.protected.original_data.as_ref().unwrap()).unwrap();
            assert_eq!(
                field(&protected, Value::Integer(1.into())),
                &Value::Integer((-7).into())
            );
            assert_eq!(
                field(&protected, Value::Integer(16.into())),
                &Value::Text("application/statuslist+cwt".into())
            );
            let cert = field(&protected, Value::Integer(33.into()))
                .as_bytes()
                .unwrap();
            assert_eq!(cert, &pem::parse(certificate()).unwrap().contents());
            let key = certificate_key(cert);
            sign1
                .verify_signature(&[], |signature, tbs| {
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key).verify(tbs, signature)
                })
                .unwrap();
            let claims = Value::from_slice(sign1.payload.as_ref().unwrap()).unwrap();
            assert_eq!(
                field(&claims, Value::Integer(2.into())),
                &Value::Text(uri.clone())
            );
            assert!(
                unsigned(field(&claims, Value::Integer(6.into())))
                    < unsigned(field(&claims, Value::Integer(4.into())))
            );
            assert!(unsigned(field(&claims, Value::Integer(65534.into()))) > 0);
            let list = field(&claims, Value::Integer(65533.into()));
            assert!([1, 2, 4, 8].contains(&unsigned(field(list, Value::Text("bits".into())))));
            assert_list(
                field(list, Value::Text("lst".into()))
                    .as_bytes()
                    .expect("lst must be a byte string"),
            );
            let aggregation = list
                .as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k == &Value::Text("aggregation_uri".into()))
                .map(|(_, v)| v);
            assert_eq!(
                aggregation,
                aggregation_uri
                    .as_ref()
                    .map(|uri| Value::Text(uri.clone()))
                    .as_ref()
            );
        }
    }
}

#[tokio::test]
async fn aggregation_body_and_list_uris_conform() {
    let app = TestServer::start(None).await;
    let aggregation_path = format!("/api/v1/aggregation/{}", app.aggregation_id);
    let response = get(&app, &aggregation_path, "application/json", "identity").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes(response).await).unwrap(),
        json!({"status_lists": [], "next_cursor": null})
    );
    let mut uris = vec![publish(&app).await, publish(&app).await];
    uris.sort();
    let response = get(&app, &aggregation_path, "application/json", "identity").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes(response).await).unwrap(),
        json!({"status_lists": uris, "next_cursor": null})
    );
    for uri in uris {
        let response = get(&app, &uri, "application/statuslist+jwt", "identity").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(verified_jwt(&bytes(response).await)["sub"], uri);
    }
}

#[tokio::test]
async fn cors_preflight_allows_public_get() {
    let app = TestServer::start(None).await;
    let aggregation_path = format!("/api/v1/aggregation/{}", app.aggregation_id);
    for path in [
        "/api/v1/aggregation",
        &aggregation_path,
        "/api/v1/status-lists/test",
    ] {
        let response = app
            .client
            .request(reqwest::Method::OPTIONS, app.url(path))
            .header("origin", "https://verifier.example")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "if-none-match")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(
            response.headers()["access-control-allow-headers"]
                .to_str()
                .unwrap()
                .split(',')
                .any(|header| header.trim() == "*"
                    || header.trim().eq_ignore_ascii_case("if-none-match"))
        );
        assert!(
            response.headers()["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .split(',')
                .any(|method| method.trim() == "GET")
        );
    }
}

#[tokio::test]
async fn jwt_gzip_conforms_for_current_and_historical_tokens() {
    let app = TestServer::start(None).await;
    let uri = publish(&app).await;
    let snapshot_time = time::OffsetDateTime::now_utc().unix_timestamp();
    for request_uri in [uri.clone(), format!("{uri}?time={snapshot_time}")] {
        for encoding in ["identity", "gzip", "gzip, deflate, br, zstd", "*"] {
            let response = get(&app, &request_uri, "application/statuslist+jwt", encoding).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "application/statuslist+jwt"
            );
            let compressed = encoding != "identity";
            if compressed {
                assert_eq!(response.headers()["content-encoding"], "gzip");
            } else {
                assert!(!response.headers().contains_key("content-encoding"));
            }
            let body = bytes(response).await;
            let mut jwt = Vec::new();
            if compressed {
                flate2::read::GzDecoder::new(body.as_slice())
                    .read_to_end(&mut jwt)
                    .unwrap();
            } else {
                jwt = body;
            }
            let claims = verified_jwt(&jwt);
            assert_eq!(claims["sub"], uri);
            assert_list(
                &BASE64_URL_SAFE_NO_PAD
                    .decode(claims["status_list"]["lst"].as_str().unwrap())
                    .unwrap(),
            );

            let response = get(&app, &request_uri, "application/statuslist+cwt", encoding).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "application/statuslist+cwt"
            );
            assert!(!response.headers().contains_key("content-encoding"));
            assert_eq!(bytes(response).await[0], 0xd2);
        }
    }
}
