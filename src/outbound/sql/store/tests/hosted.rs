//! The hosted-profile issuer store: kid resolution by primary key with no
//! cache, unique ids and keys, and reused key material rejected across
//! issuers by normalized parameters (RFC 7638 §7), not thumbprints.
#![cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres-tests"))]

#[cfg(feature = "sqlite")]
use super::fixtures;
use crate::domain::models::credential::{AggregationId, PublicJwk};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerKey, HostedIssuerKeyEntry, HostedIssuerKeyState,
    HostedIssuerState,
};
use crate::domain::ports::HostedIssuerStore;
use crate::outbound::sql::SqlHostedIssuerStore;
use time::OffsetDateTime;

const TEST_EC_JWK: &str = crate::test_fixtures::TEST_EC_PUBLIC_JWK;

fn issuer(id: &str) -> HostedIssuer {
    HostedIssuer {
        id: id.to_string(),
        display_name: Some("Portal issuer".into()),
        tier: "standard".into(),
        state: HostedIssuerState::Active,
        owner: Some("portal-operator".into()),
        created_at: OffsetDateTime::from_unix_timestamp(1_791_763_200).unwrap(),
        expires_at: Some(OffsetDateTime::from_unix_timestamp(1_799_540_800).unwrap()),
        version: 1,
        aggregation_id: AggregationId::generate(),
    }
}

fn key(issuer_id: &str, kid: &str) -> HostedIssuerKey {
    key_with_material(issuer_id, kid, TEST_EC_JWK)
}

/// A second, distinct EC key so tests that assert *material* reuse start from
/// a namespace that earlier helpers have not touched.
#[allow(dead_code)]
const ROTATED_EC_JWK: &str = r#"{"kty":"EC","crv":"P-256","kid":"rotated","alg":"ES256","x":"qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E","y":"c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"}"#;

fn key_with_material(issuer_id: &str, kid: &str, jwk_json: &str) -> HostedIssuerKey {
    let mut jwk: serde_json::Value = serde_json::from_str(jwk_json).unwrap();
    jwk["kid"] = kid.into();
    HostedIssuerKey {
        kid: kid.to_string(),
        issuer_id: issuer_id.to_string(),
        jwk: PublicJwk::try_new(serde_json::to_vec(&jwk).unwrap()).unwrap(),
        created_at: OffsetDateTime::from_unix_timestamp(1_791_763_200).unwrap(),
        not_before: None,
        not_after: None,
        state: HostedIssuerKeyState::Active,
    }
}

async fn round_trip(store: &SqlHostedIssuerStore, backend: &str) {
    let hosted = issuer("00000000-0000-4000-8000-000000000001");
    let stored = store
        .create_issuer(hosted.clone())
        .await
        .unwrap_or_else(|e| panic!("creating a hosted issuer on {backend}: {e}"));
    assert_eq!(stored.id, hosted.id, "on {backend}");
    let kid = "hosted-kid";
    store
        .add_key(key(&hosted.id, kid))
        .await
        .unwrap_or_else(|e| panic!("adding a hosted key on {backend}: {e}"));

    // `find_key_by_kid` is the resolver's read path: issuer identity, key
    // validity, and the immutable aggregation mapping in one shot.
    let found = store
        .find_key_by_kid(kid)
        .await
        .unwrap_or_else(|e| panic!("resolving a hosted kid on {backend}: {e}"))
        .expect("the key must resolve");
    let HostedIssuerKeyEntry { issuer, key } = &found;
    assert_eq!(issuer.id, hosted.id, "on {backend}");
    assert_eq!(issuer.state, HostedIssuerState::Active, "on {backend}");
    assert_eq!(key.kid, kid, "on {backend}");
    assert_eq!(key.state, HostedIssuerKeyState::Active, "on {backend}");
    assert_eq!(
        key.jwk.key_id(),
        kid,
        "the stored JWK must carry its kid on {backend}"
    );
    assert_eq!(
        issuer.aggregation_id.0, hosted.aggregation_id.0,
        "on {backend}"
    );

    assert_eq!(
        store.find_key_by_kid("never-registered").await.unwrap(),
        None,
        "an unknown kid resolves to none on {backend}"
    );
    assert_eq!(
        store.find_issuer(&hosted.id).await.unwrap().unwrap().id,
        hosted.id,
        "on {backend}"
    );
    assert_eq!(
        store.find_issuer("nobody").await.unwrap(),
        None,
        "on {backend}"
    );
}

#[allow(dead_code)]
async fn rejects_duplicates(store: &SqlHostedIssuerStore, backend: &str) {
    let first = key("00000000-0000-4000-8000-000000000003", "kid-1");
    let hosted = issuer("00000000-0000-4000-8000-000000000003");
    store.create_issuer(hosted.clone()).await.unwrap();
    assert!(
        matches!(
            store.create_issuer(hosted.clone()).await,
            Err(HostedIssuerError::AlreadyExists)
        ),
        "a duplicate hosted issuer id is a conflict on {backend}"
    );
    store
        .add_key(first)
        .await
        .unwrap_or_else(|e| panic!("adding the first key on {backend}: {e}"));
    match store.add_key(key(&hosted.id, "kid-1")).await {
        Err(HostedIssuerError::AlreadyExists) => {}
        other => panic!("a duplicate kid is a conflict on {backend}: {other:?}"),
    }
}

#[allow(dead_code)]
async fn rejects_reused_material(store: &SqlHostedIssuerStore, backend: &str) {
    // A rotated key: the earlier duplicate helpers register the base fixture.
    let key = |issuer_id: &str, kid: &str| key_with_material(issuer_id, kid, ROTATED_EC_JWK);
    let first = issuer("00000000-0000-4000-8000-000000000005");
    let second = issuer("00000000-0000-4000-8000-000000000006");

    for hosted in [&first, &second] {
        store.create_issuer(hosted.clone()).await.unwrap();
    }
    store
        .add_key(key(&first.id, "first-key"))
        .await
        .unwrap_or_else(|e| panic!("adding the first key on {backend}: {e}"));

    // Across issuers, identical material must fail closed; so must reuse
    // within one issuer under a different kid.
    assert!(
        matches!(
            store.add_key(key(&second.id, "second-key")).await,
            Err(HostedIssuerError::KeyMaterialReused(_))
        ),
        "reused material across issuers must fail closed on {backend}"
    );
    assert!(
        matches!(
            store.add_key(key(&first.id, "first-key-duplicate")).await,
            Err(HostedIssuerError::KeyMaterialReused(_))
        ),
        "reused material within one issuer must fail closed on {backend}"
    );
    // The stored row is untouched by the rejected writes.
    assert_eq!(
        store
            .find_key_by_kid("first-key")
            .await
            .unwrap()
            .expect("the stored key must survive")
            .key
            .kid,
        "first-key",
        "on {backend}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_hosted_round_trip() {
    round_trip(&sqlite_store().await, "SQLite").await;
}

#[cfg(feature = "sqlite")]
async fn sqlite_store() -> SqlHostedIssuerStore {
    // One store per helper: each helper seeds its own namespace rather than
    // having to reason about which materials earlier helpers left behind.
    SqlHostedIssuerStore::new(fixtures::sqlite_connection().await)
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_hosted_round_trip() {
    use crate::outbound::sql::test_containers::mysql_helpers;
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    round_trip(
        &SqlHostedIssuerStore::new(test_db.connection().await),
        "MySQL",
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_hosted_rejects_conflicts() {
    use crate::outbound::sql::test_containers::mysql_helpers;
    let test_db = mysql_helpers::MysqlTestDb::start().await;
    let store = SqlHostedIssuerStore::new(test_db.connection().await);
    rejects_duplicates(&store, "MySQL").await;
    rejects_reused_material(&store, "MySQL").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_hosted_round_trip() {
    use crate::outbound::sql::test_containers::postgres_helpers;
    let test_db = postgres_helpers::postgres_connection().await;
    round_trip(&SqlHostedIssuerStore::new(test_db.db.clone()), "Postgres").await;
}

#[cfg(feature = "postgres-tests")]
#[tokio::test]
async fn test_postgres_hosted_rejects_conflicts() {
    use crate::outbound::sql::test_containers::postgres_helpers;
    let test_db = postgres_helpers::postgres_connection().await;
    let store = SqlHostedIssuerStore::new(test_db.db.clone());
    rejects_duplicates(&store, "Postgres").await;
    rejects_reused_material(&store, "Postgres").await;
}
