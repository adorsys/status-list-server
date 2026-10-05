//! Draft-21 wire assertions: literal labels deliberately do not share issuer constants.
use std::io::Read;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use base64::{
    Engine as _,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use coset::{CborSerializable, TaggedCborSerializable, cbor::Value};
use serde_json::json;
use tower::ServiceExt;

use crate::{
    domain::{
        models::status_list::{Status, StatusEntry},
        service::PublishStatusListCommand,
    },
    server::AppState,
    test_utils::{test_app_state, test_certificate},
};

fn router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", crate::startup::public_read_routes())
        .layer(crate::startup::cors_layer())
        .with_state(state)
}

async fn publish(state: &AppState) -> String {
    let list_id = uuid::Uuid::new_v4().to_string();
    let uri = format!("https://example.com/api/v1/status-lists/{list_id}");
    state
        .service
        .publish_status_list(
            PublishStatusListCommand {
                list_id,
                issuer: "issuer1".into(),
                sub: uri.clone(),
                statuses: vec![
                    StatusEntry {
                        index: 0,
                        status: Status::Invalid,
                    },
                    StatusEntry {
                        index: 15,
                        status: Status::Valid,
                    },
                ],
                size: None,
                default_status: None,
            },
            &state.status_list_policy(),
        )
        .await
        .unwrap();
    uri
}

async fn get(app: &Router, uri: &str, accept: &str, encoding: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("accept", accept)
                .header("accept-encoding", encoding)
                .header("origin", "https://verifier.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
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
    assert_eq!(header.x5c.as_ref().unwrap(), &[test_certificate()]);
    let der = BASE64_STANDARD.decode(&header.x5c.unwrap()[0]).unwrap();
    let key = jsonwebtoken::DecodingKey::from_ec_der(&certificate_key(&der));
    jsonwebtoken::decode(
        token,
        &key,
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
    )
    .unwrap()
    .claims
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
        Some("https://example.com/api/v1/aggregation".to_owned()),
    ] {
        let mut state = test_app_state(None).await;
        state.aggregation_uri = aggregation_uri.clone();
        let uri = publish(&state).await;
        let app = router(state);
        let response = get(&app, &uri, "application/statuslist+jwt", "identity").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/statuslist+jwt"
        );
        assert!(!response.headers().contains_key("content-encoding"));
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["access-control-expose-headers"], "etag");
        let claims = verified_jwt(&bytes(response).await);
        assert_eq!(claims["sub"], uri);
        assert!(claims["iat"].as_i64().unwrap() < claims["exp"].as_i64().unwrap());
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
        Some("https://example.com/api/v1/aggregation".to_owned()),
    ] {
        let mut state = test_app_state(None).await;
        state.aggregation_uri = aggregation_uri.clone();
        let uri = publish(&state).await;
        let app = router(state);
        for encoding in ["identity", "gzip"] {
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
            assert_eq!(cert, &BASE64_STANDARD.decode(test_certificate()).unwrap());
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
    let state = test_app_state(None).await;
    let app = router(state.clone());
    let response = get(&app, "/api/v1/aggregation", "application/json", "identity").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes(response).await).unwrap(),
        json!({"status_lists": []})
    );
    let mut uris = vec![publish(&state).await, publish(&state).await];
    uris.sort();
    let response = get(&app, "/api/v1/aggregation", "application/json", "identity").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes(response).await).unwrap(),
        json!({"status_lists": uris})
    );
    for uri in uris {
        let response = get(&app, &uri, "application/statuslist+jwt", "identity").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(verified_jwt(&bytes(response).await)["sub"], uri);
    }
}

#[tokio::test]
async fn cors_preflight_allows_public_get() {
    let app = router(test_app_state(None).await);
    for path in ["/api/v1/aggregation", "/api/v1/status-lists/test"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(path)
                    .header("origin", "https://verifier.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "if-none-match")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(
            response.headers()["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .split(',')
                .any(|method| method.trim() == "GET")
        );
    }
}
