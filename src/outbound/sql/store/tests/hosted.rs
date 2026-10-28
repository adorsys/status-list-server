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
    let now = OffsetDateTime::now_utc();
    HostedIssuer {
        id: id.to_string(),
        display_name: Some("Portal issuer".into()),
        tier: "standard".into(),
        state: HostedIssuerState::Active,
        owner: Some("portal-operator".into()),
        created_at: now,
        expires_at: Some(now + time::Duration::days(365)),
        version: 1,
        aggregation_id: AggregationId::generate(),
    }
}

fn key(issuer_id: &str, kid: &str) -> HostedIssuerKey {
    key_with_material(issuer_id, kid, TEST_EC_JWK)
}

/// A second, distinct EC key so tests that assert *material* reuse start from
/// a namespace that earlier helpers have not touched.
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
        .unwrap_or_else(|e| panic!("creating a hosted issuer on {backend}: {e:?}"));
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
            Err(HostedIssuerError::KeyMaterialReused)
        ),
        "reused material across issuers must fail closed on {backend}"
    );
    assert!(
        matches!(
            store.add_key(key(&first.id, "first-key-duplicate")).await,
            Err(HostedIssuerError::KeyMaterialReused)
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
#[tokio::test]
async fn test_sqlite_hosted_rejects_conflicts() {
    let store = sqlite_store().await;
    rejects_duplicates(&store, "SQLite").await;
    rejects_reused_material(&store, "SQLite").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_add_key_to_missing_issuer_is_not_found() {
    let store = sqlite_store().await;
    match store.add_key(key("nobody", "orphan-key")).await {
        Err(HostedIssuerError::NotFound) => {}
        other => panic!("a missing issuer must be NotFound, got {other:?}"),
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_add_key_stores_the_requested_state() {
    let store = sqlite_store().await;
    let hosted = issuer("00000000-0000-4000-8000-00000000000a");
    store.create_issuer(hosted.clone()).await.unwrap();
    let mut revoked = key(&hosted.id, "revoked-key");
    revoked.state = HostedIssuerKeyState::Revoked;
    store.add_key(revoked.clone()).await.unwrap();

    let found = store
        .find_key_by_kid("revoked-key")
        .await
        .unwrap()
        .expect("the revoked key must resolve to its row");
    assert_eq!(
        found.key.state,
        HostedIssuerKeyState::Revoked,
        "the stored state must match the requested state"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_non_portal_issuer_is_invisible() {
    use crate::outbound::sql::models::issuers;
    use sea_orm::ActiveValue::Set;
    use sea_orm::EntityTrait;

    let db = fixtures::sqlite_connection().await;
    let store = SqlHostedIssuerStore::new(db.clone());
    // A registry/credential row in the shared table, without the `portal` source.
    issuers::Entity::insert(issuers::ActiveModel {
        issuer: Set("credential-issuer".to_string()),
        aggregation_id: Set(Some(
            crate::domain::models::credential::AggregationId::generate().to_string(),
        )),
        list_count: Set(0),
        display_name: Set(None),
        source: Set("registry".to_string()),
        tier: Set("standard".to_string()),
        state: Set("active".to_string()),
        owner: Set(None),
        created_at: Set(0),
        expires_at: Set(None),
        version: Set(0),
    })
    .exec_without_returning(&*db)
    .await
    .unwrap();

    assert_eq!(
        store.find_issuer("credential-issuer").await.unwrap(),
        None,
        "a non-portal issuer must not resolve as hosted"
    );
    match store.add_key(key("credential-issuer", "stray-key")).await {
        Err(HostedIssuerError::NotFound) => {}
        other => panic!("a key for a non-portal issuer must be NotFound, got {other:?}"),
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_issuer_id_collision_is_a_conflict() {
    let store = sqlite_store().await;
    let hosted = issuer("00000000-0000-4000-8000-00000000000b");
    store.create_issuer(hosted.clone()).await.unwrap();
    match store.create_issuer(hosted.clone()).await {
        Err(HostedIssuerError::AlreadyExists) => {}
        other => panic!("a duplicate issuer id must be AlreadyExists, got {other:?}"),
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_concurrent_same_material_adds_allow_exactly_one() {
    let store = sqlite_store().await;
    let first = issuer("00000000-0000-4000-8000-00000000000c");
    let second = issuer("00000000-0000-4000-8000-00000000000d");
    store.create_issuer(first.clone()).await.unwrap();
    store.create_issuer(second.clone()).await.unwrap();

    // Same material under different kids, registered concurrently. The
    // `key_material` unique index guarantees exactly one wins; the other gets
    // a typed KeyMaterialReused, never a silent duplicate.
    let (a, b) = tokio::join!(
        store.add_key(key(&first.id, "concurrent-a")),
        store.add_key(key(&second.id, "concurrent-b")),
    );
    let outcomes = [a, b];
    assert_eq!(
        outcomes.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one concurrent registration of the same material must win"
    );
    assert!(
        outcomes
            .iter()
            .any(|result| matches!(result, Err(HostedIssuerError::KeyMaterialReused))),
        "the losing registration must be a typed KeyMaterialReused"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_malformed_row_is_quarantined_not_fatal() {
    use crate::outbound::sql::models::PublicKey;
    use crate::outbound::sql::models::hosted_issuer_keys;
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::ActiveValue::Set;
    use sea_orm::EntityTrait;

    let db = fixtures::sqlite_connection().await;
    let store = SqlHostedIssuerStore::new(db.clone());
    let hosted = issuer("00000000-0000-4000-8000-00000000000e");
    store.create_issuer(hosted.clone()).await.unwrap();
    store.add_key(key(&hosted.id, "good-key")).await.unwrap();

    // A structurally-valid Jwk that PublicJwk::try_new rejects (kty=oct),
    // inserted directly as an old pod or manual edit could.
    let bad: Jwk = serde_json::from_value(
        serde_json::json!({"kty":"oct","kid":"bad-key","alg":"HS256","k":"c2VjcmV0"}),
    )
    .unwrap();
    hosted_issuer_keys::Entity::insert(hosted_issuer_keys::ActiveModel {
        kid: Set("bad-key".to_string()),
        issuer_id: Set(hosted.id.clone()),
        key_material: Set("b".repeat(64)),
        alg: Set("HS256".to_string()),
        jwk: Set(PublicKey(bad)),
        state: Set("active".to_string()),
        not_before: Set(None),
        not_after: Set(None),
        created_at: Set(0),
    })
    .exec_without_returning(&*db)
    .await
    .unwrap();

    // all_keys() (the startup/reload scan) must not fail because of it; the
    // malformed row is quarantined and the rest still resolves.
    let keys = store.all_keys().await.unwrap();
    let kids: Vec<&str> = keys.iter().map(|key| key.kid.as_str()).collect();
    assert!(kids.contains(&"good-key"));
    assert!(
        !kids.contains(&"bad-key"),
        "the malformed row must be quarantined"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_stored_alg_is_the_jose_name() {
    use crate::outbound::sql::models::hosted_issuer_keys;
    use sea_orm::EntityTrait;

    let db = fixtures::sqlite_connection().await;
    let store = SqlHostedIssuerStore::new(db.clone());
    let hosted = issuer("00000000-0000-4000-8000-00000000000f");
    store.create_issuer(hosted.clone()).await.unwrap();
    store.add_key(key(&hosted.id, "alg-key")).await.unwrap();

    let row = hosted_issuer_keys::Entity::find_by_id("alg-key")
        .one(&*db)
        .await
        .unwrap()
        .expect("the key must be stored");
    assert_eq!(
        row.alg, "ES256",
        "the alg column must hold the JOSE name, not a Debug representation"
    );
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
