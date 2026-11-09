//! SQL adapter for the hosted-profile issuer store. A hosted issuer is a
//! row of the shared ownership table (`issuers`, expanded by the
//! `hosted_issuers` migration), so creating one records its aggregation ID
//! and its ownership/quota slot in the same unit; keys live in
//! `issuer_keys`. Dynamic keys resolve per request by `kid` primary key
//! with no cache, so revocation takes effect on the next request.

use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait, Order,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    sea_query::{Expr, OnConflict},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use time::OffsetDateTime;

use super::error::{RepositoryError, contention_err};
use super::models::{
    PublicKey, hosted_issuer_keys, issuer_audit_events, issuers, registry_static_claims,
    static_key_revocations,
};
use super::store::{SeaOrmStore, SwappableDatabaseConnection, begin_read_committed, find_err};
use crate::domain::models::credential::{AggregationId, PublicJwk, canonical_jwk_material};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerFilter, HostedIssuerKey, HostedIssuerKeyEntry,
    HostedIssuerKeyState, HostedIssuerReadState, HostedIssuerState,
};
use crate::domain::models::tier::{IssuerTier, Tiers};
use crate::domain::ports::{
    HostedIssuerLifecycleStore, HostedIssuerStore, RegistryWriteGuard, StaticClaimConflict,
};
use crate::utils::metrics_db::time_query;

/// How often a creation regenerates a colliding random aggregation ID. 122
/// random bits colliding inside one deployment is a fault threshold, not a
/// loop bound.
const AGGREGATION_ID_RETRIES: u32 = 3;

/// The `source` value marking a row as a hosted-profile issuer. Rows
/// written by the registry or credential paths carry the migration default and
/// must never be treated as hosted.
const PORTAL_SOURCE: &str = "portal";

#[derive(Clone)]
pub(crate) enum HostedIssuerRow {}

#[derive(Clone)]
pub struct SqlHostedIssuerStore {
    store: SeaOrmStore<HostedIssuerRow>,
    key_limits: Option<Arc<Tiers>>,
}

impl SqlHostedIssuerStore {
    pub fn new(db: Arc<sea_orm::DatabaseConnection>) -> Self {
        Self {
            store: SeaOrmStore::new(db),
            key_limits: None,
        }
    }

    pub fn from_handle(db: Arc<SwappableDatabaseConnection>) -> Self {
        Self {
            store: SeaOrmStore::from_handle(db),
            key_limits: None,
        }
    }

    /// Refuse a key that would take an issuer past its stored tier's
    /// `max_keys`, as the registry does for its own issuers.
    pub fn with_key_limits(mut self, tiers: Arc<Tiers>) -> Self {
        self.key_limits = Some(tiers);
        self
    }
}

fn map_insert_err(e: DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string())),
    }
}

/// A failure after the transaction errored out: Postgres marks it failed
/// (25P02) and MySQL may hold locks (1205) until an explicit rollback, so the
/// rollback runs before the driver error is classified.
async fn classify_after_rollback(
    txn: sea_orm::DatabaseTransaction,
    insert_err: DbErr,
    what: &str,
) -> RepositoryError {
    if let Err(rollback_err) = txn.rollback().await {
        return RepositoryError::InsertError(format!(
            "{what} failed ({insert_err}); \
             rolling the transaction back also failed: {rollback_err}"
        ));
    }
    map_insert_err(insert_err)
}

fn try_from_unix(seconds: i64) -> Result<OffsetDateTime, RepositoryError> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|e| RepositoryError::DataError(e.to_string()))
}

/// A hosted `issuers` row must carry its aggregation ID and a source of
/// `portal`: metadata added by the hosted migration that another trust
/// source leaves defaulted. A row without the mapping cannot resolve, so
/// aggregation-less registry rows stay unreachable through this adapter.
fn parse_issuer(row: issuers::Model) -> Result<HostedIssuer, RepositoryError> {
    let aggregation_id = match row.aggregation_id.as_deref().map(str::parse) {
        Some(Ok(uuid)) => AggregationId(uuid),
        Some(Err(e)) => {
            return Err(RepositoryError::DataError(format!(
                "hosted issuer `{}` has an unusable aggregation mapping: {e}",
                row.issuer
            )));
        }
        None => {
            return Err(RepositoryError::DataError(format!(
                "hosted issuer `{}` has no aggregation mapping",
                row.issuer
            )));
        }
    };
    let created_at = try_from_unix(row.created_at)?;
    let expires_at = match row.expires_at {
        Some(seconds) => Some(try_from_unix(seconds)?),
        None => None,
    };
    let state = match row.state.as_str() {
        value if value == HostedIssuerState::Active.as_str() => HostedIssuerState::Active,
        value if value == HostedIssuerState::Suspended.as_str() => HostedIssuerState::Suspended,
        "disabled" => HostedIssuerState::Suspended,
        other => {
            return Err(RepositoryError::DataError(format!(
                "hosted issuer `{}` has unknown state `{other}`",
                row.issuer
            )));
        }
    };
    Ok(HostedIssuer {
        id: row.issuer,
        display_name: row.display_name,
        tier: row.tier,
        state,
        owner: row.owner,
        created_at,
        expires_at,
        version: row.version.max(0) as u64,
        aggregation_id,
    })
}

fn parse_key(row: hosted_issuer_keys::Model) -> Result<HostedIssuerKey, RepositoryError> {
    let not_before = match row.not_before {
        Some(seconds) => Some(try_from_unix(seconds)?),
        None => None,
    };
    let not_after = match row.not_after {
        Some(seconds) => Some(try_from_unix(seconds)?),
        None => None,
    };
    let state = match row.state.as_str() {
        value if value == HostedIssuerKeyState::Active.as_str() => HostedIssuerKeyState::Active,
        value if value == HostedIssuerKeyState::Reserved.as_str() => HostedIssuerKeyState::Reserved,
        value if value == HostedIssuerKeyState::Revoked.as_str() => HostedIssuerKeyState::Revoked,
        other => {
            return Err(RepositoryError::DataError(format!(
                "issuer key `{}` has unknown state `{other}`",
                row.kid
            )));
        }
    };
    let bytes = serde_json::to_vec(&row.jwk)
        .map_err(|e| RepositoryError::DataError(format!("stored hosted JWK serialization: {e}")))?;
    Ok(HostedIssuerKey {
        kid: row.kid,
        issuer_id: row.issuer_id,
        jwk: PublicJwk::try_new(bytes).map_err(|e| RepositoryError::DataError(e.to_string()))?,
        created_at: try_from_unix(row.created_at)?,
        not_before,
        not_after,
        state,
    })
}

fn parse_entry(
    issuer: issuers::Model,
    key: hosted_issuer_keys::Model,
) -> Result<HostedIssuerKeyEntry, RepositoryError> {
    Ok(HostedIssuerKeyEntry {
        issuer: parse_issuer(issuer)?,
        key: parse_key(key)?,
    })
}

/// Resolve a key row together with its hosted issuer. Malformed stored data is
/// a permanent fault (`DataError`), never an empty result or a transient error.
async fn load_entry(
    kid: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<HostedIssuerKeyEntry>, RepositoryError> {
    let key = hosted_issuer_keys::Entity::find_by_id(kid)
        .one(db)
        .await
        .map_err(find_err)?;
    let Some(key) = key else {
        return Ok(None);
    };
    let issuer = issuers::Entity::find_by_id(&key.issuer_id)
        .filter(issuers::Column::Source.is_in([
            PORTAL_SOURCE,
            super::migrations::issuer_keys_carry_over::CARRIED_SOURCE,
        ]))
        .one(db)
        .await
        .map_err(find_err)?
        .ok_or_else(|| {
            RepositoryError::DataError(format!("issuer key `{kid}` has no issuer row"))
        })?;
    Some(parse_entry(issuer, key)).transpose()
}

async fn load_issuer(
    id: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<HostedIssuer>, RepositoryError> {
    let issuer = issuers::Entity::find()
        .filter(exact_text_eq(
            "issuers.issuer",
            id,
            db.get_database_backend(),
        ))
        .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
        .one(db)
        .await
        .map_err(find_err)?;
    match issuer {
        Some(row) => Ok(Some(parse_issuer(row)?)),
        None => Ok(None),
    }
}

fn exact_text_eq(
    column: &str,
    value: &str,
    backend: DatabaseBackend,
) -> sea_orm::sea_query::SimpleExpr {
    let expression = match backend {
        DatabaseBackend::MySql => format!("BINARY {column} = ?"),
        DatabaseBackend::Postgres => {
            format!("convert_to({column}, 'UTF8') = convert_to($1, 'UTF8')")
        }
        DatabaseBackend::Sqlite => format!("{column} COLLATE BINARY = ?"),
        _ => format!("{column} = ?"),
    };
    Expr::cust_with_values(expression, [value])
}

fn bytewise_text_order(column: &str, backend: DatabaseBackend) -> sea_orm::sea_query::SimpleExpr {
    let expression = match backend {
        DatabaseBackend::MySql => format!("BINARY {column}"),
        DatabaseBackend::Postgres => format!("convert_to({column}, 'UTF8')"),
        DatabaseBackend::Sqlite => format!("{column} COLLATE BINARY"),
        _ => column.to_owned(),
    };
    Expr::cust(expression)
}

fn bytewise_text_after(
    column: &str,
    value: &str,
    backend: DatabaseBackend,
) -> sea_orm::sea_query::SimpleExpr {
    let expression = match backend {
        DatabaseBackend::MySql => format!("BINARY {column} > BINARY ?"),
        DatabaseBackend::Postgres => {
            format!("convert_to({column}, 'UTF8') > convert_to($1, 'UTF8')")
        }
        DatabaseBackend::Sqlite => format!("{column} COLLATE BINARY > ?"),
        _ => format!("{column} > ?"),
    };
    Expr::cust_with_values(expression, [value])
}

async fn insert_issuer_row(
    txn: &sea_orm::DatabaseTransaction,
    issuer: &HostedIssuer,
) -> Result<(), DbErr> {
    issuers::Entity::insert(issuers::ActiveModel {
        issuer: Set(issuer.id.clone()),
        aggregation_id: Set(Some(issuer.aggregation_id.to_string())),
        list_count: Set(0),
        display_name: Set(issuer.display_name.clone()),
        source: Set("portal".to_string()),
        tier: Set(issuer.tier.clone()),
        state: Set(issuer.state.as_str().to_string()),
        owner: Set(issuer.owner.clone()),
        created_at: Set(issuer.created_at.unix_timestamp()),
        expires_at: Set(issuer.expires_at.map(|value| value.unix_timestamp())),
        version: Set(issuer.version.min(i64::MAX as u64) as i64),
    })
    .exec_without_returning(txn)
    .await
    .map(|_| ())
}

async fn insert_key_row(
    txn: &sea_orm::DatabaseTransaction,
    key: &HostedIssuerKey,
    key_material: &str,
) -> Result<(), DbErr> {
    hosted_issuer_keys::Entity::insert(hosted_issuer_keys::ActiveModel {
        kid: Set(key.kid.clone()),
        issuer_id: Set(key.issuer_id.clone()),
        key_material: Set(key_material.to_owned()),
        alg: Set(jose_alg_name(key.jwk.algorithm()).to_owned()),
        jwk: Set(PublicKey::from(key.jwk.jwk().clone())),
        state: Set(key.state.as_str().to_owned()),
        not_before: Set(key.not_before.map(|value| value.unix_timestamp())),
        not_after: Set(key.not_after.map(|value| value.unix_timestamp())),
        created_at: Set(key.created_at.unix_timestamp()),
    })
    .exec_without_returning(txn)
    .await
    .map(|_| ())
}

fn validate_key_window(key: &HostedIssuerKey) -> Result<(), RepositoryError> {
    if key.jwk.key_id() != key.kid {
        return Err(RepositoryError::InvalidKey(format!(
            "key `{}` has conflicting JWK kid metadata",
            key.kid
        )));
    }
    if key
        .not_before
        .zip(key.not_after)
        .is_some_and(|(before, after)| before >= after)
    {
        return Err(RepositoryError::InvalidKey(format!(
            "key `{}` has not_before >= not_after",
            key.kid
        )));
    }
    Ok(())
}

/// Whether a `DbErr` is a unique-constraint violation, which is how both the
/// issuer `id` primary key and the `aggregation_id` unique index surface a
/// collision on insert.
fn is_unique_violation(err: &DbErr) -> bool {
    matches!(
        err.sql_err(),
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
    )
}

/// SHA-256 of the canonical key parameters, hex-encoded. The `key_material`
/// column is unique-indexed on this so material reuse is rejected by the
/// database rather than a race-prone application scan.
fn material_hash(material: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(material.as_bytes()))
}

fn static_claim_hash(kind: &str, value: &str) -> String {
    material_hash(&format!("{kind}:{value}"))
}

/// The JOSE `alg` name for a validated management key. `PublicJwk` restricts
/// the algorithm to this set, so the `alg` column stores a stable data contract
/// rather than a `Debug` representation.
fn jose_alg_name(algorithm: jsonwebtoken::Algorithm) -> &'static str {
    match algorithm {
        jsonwebtoken::Algorithm::ES256 => "ES256",
        jsonwebtoken::Algorithm::ES384 => "ES384",
        jsonwebtoken::Algorithm::EdDSA => "EdDSA",
        jsonwebtoken::Algorithm::PS256 => "PS256",
        other => unreachable!("management keys cannot use `{other:?}`"),
    }
}

/// The hosted key row that already holds the given material hash, if any.
async fn find_key_by_material_hash(
    hash: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<HostedIssuerKey>, RepositoryError> {
    let row = hosted_issuer_keys::Entity::find()
        .filter(hosted_issuer_keys::Column::KeyMaterial.eq(hash))
        .one(db)
        .await
        .map_err(find_err)?;
    row.map(parse_key).transpose()
}

impl SeaOrmStore<HostedIssuerRow> {
    #[tracing::instrument(skip(self, issuer), fields(db.system = "sea-orm"))]
    async fn create_issuer_unit(
        &self,
        issuer: HostedIssuer,
        actor: &str,
    ) -> Result<HostedIssuer, RepositoryError> {
        time_query("insert", "hosted_issuer", async {
            let db = self.current();
            let mut stored = issuer;
            for attempt in 0..AGGREGATION_ID_RETRIES {
                if attempt > 0 {
                    stored.aggregation_id = AggregationId::generate();
                }
                let txn = begin_read_committed(&db).await.map_err(insert_first_err)?;
                match insert_issuer_row(&txn, &stored).await {
                    Ok(()) => {
                        if let Err(error) = append_lifecycle_audit(
                            &txn,
                            &stored.id,
                            actor,
                            "issuer.created",
                            None,
                            Some(serde_json::json!({
                                "state": stored.state.as_str(),
                                "version": stored.version,
                                "aggregation_id": stored.aggregation_id.0,
                            })),
                        )
                        .await
                        {
                            rollback_quietly(txn).await;
                            return Err(err_txn(error));
                        }
                        txn.commit().await.map_err(map_insert_err)?;
                        // The row stores whole-second timestamps; return what was
                        // persisted so the returned issuer matches a re-read.
                        stored.created_at = stored
                            .created_at
                            .replace_nanosecond(0)
                            .unwrap_or(stored.created_at);
                        stored.expires_at = stored
                            .expires_at
                            .map(|value| value.replace_nanosecond(0).unwrap_or(value));
                        return Ok(stored);
                    }
                    Err(err) if is_unique_violation(&err) => {
                        // A unique violation is the issuer `id` primary key
                        // (the id was already taken) or the `aggregation_id`
                        // unique index (a random collision). Postgres aborts
                        // the transaction, so roll back before deciding.
                        txn.rollback().await.ok();
                        if issuers::Entity::find_by_id(&stored.id)
                            .one(&*db)
                            .await
                            .map_err(find_err)?
                            .is_some()
                        {
                            return Err(RepositoryError::DuplicateEntry);
                        }
                        // The id was free, so the unique violation was the
                        // random aggregation ID: regenerate and retry.
                        continue;
                    }
                    Err(err) => {
                        return Err(classify_after_rollback(txn, err, "hosted issuer insert").await);
                    }
                }
            }
            Err(RepositoryError::InsertError(
                "every generated aggregation ID collided with one already in use".into(),
            ))
        })
        .await
    }

    async fn add_key_if_version(
        &self,
        key: HostedIssuerKey,
        expected_version: Option<u64>,
        key_limits: Option<&Tiers>,
        actor: &str,
    ) -> Result<(), RepositoryError> {
        validate_key_window(&key)?;
        time_query("insert", "issuer_key", async {
            let material = serde_json::from_slice::<serde_json::Value>(key.jwk.as_bytes())
                .map_err(|err| RepositoryError::InvalidKey(err.to_string()))
                .and_then(|value| canonical_jwk_material(&value).map_err(err_jwk))?;
            let hash = material_hash(&material);
            let db = self.current();
            let txn = begin_read_committed(&db).await.map_err(insert_first_err)?;
            let issuer = issuers::Entity::find_by_id(&key.issuer_id)
                .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
                .one(&txn)
                .await;
            let issuer = match issuer {
                Ok(issuer) => issuer,
                Err(error) => {
                    rollback_quietly(txn).await;
                    return Err(err_txn(error));
                }
            };
            let Some(issuer) = issuer else {
                txn.rollback().await.ok();
                return Err(RepositoryError::NotFound);
            };
            if expected_version.is_some_and(|expected| issuer.version != expected as i64) {
                txn.rollback().await.ok();
                return Err(RepositoryError::VersionMismatch);
            }
            let locked = issuers::Entity::update_many()
                .col_expr(
                    issuers::Column::Version,
                    sea_orm::sea_query::ExprTrait::add(Expr::col(issuers::Column::Version), 1),
                )
                .filter(issuers::Column::Issuer.eq(&key.issuer_id))
                .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
                .filter(issuers::Column::Version.eq(issuer.version))
                .exec(&txn)
                .await;
            match locked {
                Ok(result) if result.rows_affected > 0 => {}
                Ok(_) => {
                    txn.rollback().await.ok();
                    return Err(RepositoryError::VersionMismatch);
                }
                Err(err) => {
                    return Err(classify_after_rollback(txn, err, "issuer key lock").await);
                }
            }
            let now = OffsetDateTime::now_utc();
            if let Some(tiers) = key_limits
                && key.counts_against_quota(now)
                && let Err(err) = check_key_quota(&txn, &key.issuer_id, tiers, now).await
            {
                txn.rollback().await.ok();
                return Err(err);
            }
            let insert = insert_key_row(&txn, &key, &hash).await;
            match insert {
                Ok(_) => {
                    if let Err(error) = append_lifecycle_audit(
                        &txn,
                        &key.issuer_id,
                        actor,
                        "key.registered",
                        None,
                        Some(serde_json::json!({"kid": key.kid, "state": key.state.as_str(), "version": issuer.version + 1})),
                    )
                    .await
                    {
                        rollback_quietly(txn).await;
                        return Err(err_txn(error));
                    }
                    txn.commit().await.map_err(map_insert_err)?;
                    Ok(())
                }
                Err(insert_err) => {
                    let classified =
                        classify_after_rollback(txn, insert_err, "issuer key insert").await;
                    // A unique violation is either the `kid` primary key (the id
                    // was already taken) or the `key_material` index (the
                    // material is reused by another issuer). Distinguish by what
                    // is already stored.
                    if matches!(classified, RepositoryError::DuplicateEntry) {
                        if load_entry(&key.kid, &db).await?.is_some() {
                            return Err(RepositoryError::DuplicateEntry);
                        }
                        if let Some(blocker) =
                            find_key_by_material_hash(&material_hash(&material), &db).await?
                        {
                            // Log the owner server-side; never return it, so one
                            // tenant cannot learn another tenant's id.
                            tracing::warn!(
                                kid = %key.kid,
                                owner = %blocker.issuer_id,
                                "rejecting a hosted key whose material is already registered"
                            );
                            return Err(RepositoryError::KeyMaterialReused);
                        }
                        return Err(classified);
                    }
                    Err(classified)
                }
            }
        })
        .await
    }

    async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, RepositoryError> {
        time_query("find_all", "issuer_key", async {
            let rows = hosted_issuer_keys::Entity::find()
                .all(self.current().as_ref())
                .await
                .map_err(find_err)?;
            // A row that no longer parses (e.g. after a validation rule
            // tightened) must not take down the whole deployment on the
            // startup/reload scan: quarantine it, log it, and keep going.
            // Per-kid reads still fail closed for exactly that kid.
            let mut keys = Vec::with_capacity(rows.len());
            for row in rows {
                match parse_key(row) {
                    Ok(key) => keys.push(key),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "quarantining a hosted issuer key row that no longer parses"
                        );
                    }
                }
            }
            Ok(keys)
        })
        .await
    }

    async fn all_issuers(&self) -> Result<Vec<HostedIssuer>, RepositoryError> {
        time_query("find_all", "hosted_issuer", async {
            let rows = issuers::Entity::find()
                .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
                .all(self.current().as_ref())
                .await
                .map_err(find_err)?;
            // Quarantined like `all_keys`: one malformed row must not hide
            // every other issuer from the scan.
            let mut hosted = Vec::with_capacity(rows.len());
            for row in rows {
                match parse_issuer(row) {
                    Ok(issuer) => hosted.push(issuer),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "skipping a hosted issuer row that no longer parses"
                        );
                    }
                }
            }
            Ok(hosted)
        })
        .await
    }

    async fn find_entry_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<HostedIssuerKeyEntry>, RepositoryError> {
        time_query("find_by_kid", "issuer_key", async {
            load_entry(kid, self.current().as_ref()).await
        })
        .await
    }

    async fn find_key_by_material(
        &self,
        material: &str,
    ) -> Result<Option<HostedIssuerKey>, RepositoryError> {
        time_query("find_material", "issuer_key", async {
            let hash = material_hash(material);
            find_key_by_material_hash(&hash, self.current().as_ref()).await
        })
        .await
    }

    async fn find_issuer_ids(&self, ids: &[String]) -> Result<HashSet<String>, RepositoryError> {
        time_query("find_ids", "hosted_issuer", async {
            let db = self.current();
            let mut found = HashSet::new();
            // Chunked to stay under each backend's bind-variable limit.
            for chunk in ids.chunks(500) {
                let rows = issuers::Entity::find()
                    .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
                    .filter(issuers::Column::Issuer.is_in(chunk.iter().cloned()))
                    .all(db.as_ref())
                    .await
                    .map_err(find_err)?;
                found.extend(rows.into_iter().map(|row| row.issuer));
            }
            Ok(found)
        })
        .await
    }
}

/// Fails with `KeyQuotaExceeded` when `issuer_id` already holds its stored
/// tier's `max_keys` keys that count against the quota at `now`. An unknown
/// tier name gets the strictest tier, as when the issuer authenticates.
async fn check_key_quota(
    txn: &sea_orm::DatabaseTransaction,
    issuer_id: &str,
    tiers: &Tiers,
    now: OffsetDateTime,
) -> Result<(), RepositoryError> {
    let tier = issuers::Entity::find_by_id(issuer_id)
        .select_only()
        .column(issuers::Column::Tier)
        .into_tuple::<String>()
        .one(txn)
        .await
        .map_err(find_err)?
        .ok_or(RepositoryError::NotFound)?;
    let max_keys = tiers
        .get(IssuerTier::from_name_or_strictest(&tier))
        .max_keys;
    let held = hosted_issuer_keys::Entity::find()
        .filter(hosted_issuer_keys::Column::IssuerId.eq(issuer_id))
        .filter(hosted_issuer_keys::Column::State.eq(HostedIssuerKeyState::Active.as_str()))
        .filter(
            Condition::any()
                .add(hosted_issuer_keys::Column::NotAfter.is_null())
                .add(hosted_issuer_keys::Column::NotAfter.gt(now.unix_timestamp())),
        )
        .count(txn)
        .await
        .map_err(find_err)?;
    if usize::try_from(held).unwrap_or(usize::MAX) >= max_keys {
        return Err(RepositoryError::KeyQuotaExceeded { max_keys });
    }
    Ok(())
}

/// Only the typed material-reuse, key-quota and invalid-key variants from
/// `add_key` are recoverable here; everything else keeps the shared mapping.
fn hosted_error(err: RepositoryError) -> HostedIssuerError {
    match &err {
        RepositoryError::KeyMaterialReused => HostedIssuerError::KeyMaterialReused,
        RepositoryError::VersionMismatch => HostedIssuerError::VersionMismatch,
        RepositoryError::KeyQuotaExceeded { max_keys } => HostedIssuerError::KeyQuotaExceeded {
            max_keys: *max_keys,
        },
        RepositoryError::InvalidKey(message) => {
            HostedIssuerError::InvalidPublicJwk(message.clone())
        }
        _ => err.into(),
    }
}

fn err_txn(e: DbErr) -> RepositoryError {
    contention_err(&e).unwrap_or_else(|| find_err(e))
}

/// Aborts a lifecycle transaction before a domain early return. Postgres
/// marks a failed transaction unusable and MySQL may hold its locks until an
/// explicit rollback, so the transaction is never silently dropped.
async fn rollback_quietly(txn: sea_orm::DatabaseTransaction) {
    if let Err(error) = txn.rollback().await {
        tracing::warn!(%error, "rolling back an aborted lifecycle transaction failed");
    }
}

async fn revoked_key_after_rollback(
    db: &sea_orm::DatabaseConnection,
    issuer_id: &str,
    kid: &str,
) -> Result<HostedIssuerKey, HostedIssuerError> {
    let current = hosted_issuer_keys::Entity::find_by_id(kid)
        .filter(hosted_issuer_keys::Column::IssuerId.eq(issuer_id))
        .one(db)
        .await
        .map_err(err_txn)?
        .ok_or(HostedIssuerError::NotFound)?;
    let current = parse_key(current).map_err(HostedIssuerError::from)?;
    if current.state == HostedIssuerKeyState::Revoked {
        Ok(current)
    } else {
        Err(HostedIssuerError::VersionMismatch)
    }
}

fn err_jwk(message: String) -> RepositoryError {
    RepositoryError::InvalidKey(format!("invalid public JWK: {message}"))
}

fn insert_first_err(e: DbErr) -> RepositoryError {
    RepositoryError::InsertError(format!("hosted write failed to open a transaction: {e}"))
}

#[async_trait]
impl HostedIssuerStore for SqlHostedIssuerStore {
    async fn registry_write_guard(&self) -> Result<Box<dyn RegistryWriteGuard>, HostedIssuerError> {
        let db = self.store.current();
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            // SQLite is a single-node backend; the local registry lock covers its writes.
            return Ok(Box::new(()));
        }
        let txn = begin_read_committed(&db).await.map_err(err_txn)?;
        let row = txn
            .query_one_raw(sea_orm::Statement::from_string(
                db.get_database_backend(),
                "SELECT id FROM registry_write_guard WHERE id = 1 FOR UPDATE",
            ))
            .await
            .map_err(err_txn)?;
        if row.is_none() {
            return Err(HostedIssuerError::Unavailable);
        }
        Ok(Box::new(txn))
    }

    async fn record_static_registry_claims(
        &self,
        keys: &[(String, String, String)],
    ) -> Result<(), HostedIssuerError> {
        if keys.is_empty() {
            return Ok(());
        }
        let db = self.store.current();
        let txn = begin_read_committed(&db).await.map_err(err_txn)?;
        for (id, kid, material) in keys {
            for claim in [
                static_claim_hash("id", id),
                static_claim_hash("kid", kid),
                static_claim_hash("material", material),
            ] {
                registry_static_claims::Entity::insert(registry_static_claims::ActiveModel {
                    claim: Set(claim),
                })
                .on_conflict(
                    OnConflict::column(registry_static_claims::Column::Claim)
                        .do_nothing_on([registry_static_claims::Column::Claim])
                        .to_owned(),
                )
                .exec_without_returning(&txn)
                .await
                .map_err(err_txn)?;
            }
        }
        txn.commit().await.map_err(err_txn)?;
        Ok(())
    }

    async fn static_claim_conflict(
        &self,
        issuer_id: &str,
        kid: Option<&str>,
        material: Option<&str>,
    ) -> Result<Option<StaticClaimConflict>, HostedIssuerError> {
        let db = self.store.current();
        for (claim, conflict) in [
            (
                Some(static_claim_hash("id", issuer_id)),
                StaticClaimConflict::PrincipalId,
            ),
            (
                kid.map(|value| static_claim_hash("kid", value)),
                StaticClaimConflict::KeyId,
            ),
            (
                material.map(|value| static_claim_hash("material", value)),
                StaticClaimConflict::KeyMaterial,
            ),
        ] {
            if let Some(claim) = claim
                && registry_static_claims::Entity::find_by_id(claim)
                    .one(db.as_ref())
                    .await
                    .map_err(find_err)?
                    .is_some()
            {
                return Ok(Some(conflict));
            }
        }
        Ok(None)
    }

    async fn record_static_key_revocations(
        &self,
        revocations: &[crate::domain::ports::StaticKeyRevocation],
    ) -> Result<(), HostedIssuerError> {
        if revocations.is_empty() {
            return Ok(());
        }
        let db = self.store.current();
        let txn = begin_read_committed(&db).await.map_err(find_err)?;
        let rows = revocations
            .iter()
            .map(|revocation| static_key_revocations::ActiveModel {
                kid: Set(revocation.kid.clone()),
                material: Set(material_hash(&revocation.material)),
            });
        let inserted = static_key_revocations::Entity::insert_many(rows)
            .on_conflict(
                OnConflict::column(static_key_revocations::Column::Kid)
                    .do_nothing_on([static_key_revocations::Column::Kid])
                    .to_owned(),
            )
            .exec_without_returning(&txn)
            .await;
        if let Err(error) = inserted {
            rollback_quietly(txn).await;
            return Err(hosted_error(map_insert_err(error)));
        }
        let kids: Vec<_> = revocations.iter().map(|entry| entry.kid.clone()).collect();
        let existing = static_key_revocations::Entity::find()
            .filter(static_key_revocations::Column::Kid.is_in(kids))
            .all(&txn)
            .await;
        let existing = match existing {
            Ok(rows) => rows
                .into_iter()
                .map(|row| (row.kid, row.material))
                .collect::<HashMap<_, _>>(),
            Err(error) => {
                rollback_quietly(txn).await;
                return Err(find_err(error).into());
            }
        };
        for revocation in revocations {
            match existing.get(&revocation.kid) {
                Some(hash) if *hash == material_hash(&revocation.material) => {}
                Some(_) => {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::AlreadyExists);
                }
                None => {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::Unavailable);
                }
            }
        }
        txn.commit().await.map_err(find_err)?;
        Ok(())
    }

    async fn static_key_was_revoked(
        &self,
        kid: &str,
        material: &str,
    ) -> Result<bool, HostedIssuerError> {
        let material_hash = material_hash(material);
        static_key_revocations::Entity::find()
            .filter(
                Condition::any()
                    .add(static_key_revocations::Column::Kid.eq(kid))
                    .add(static_key_revocations::Column::Material.eq(material_hash)),
            )
            .one(self.store.current().as_ref())
            .await
            .map(|row| row.is_some())
            .map_err(find_err)
            .map_err(Into::into)
    }

    async fn static_keys_were_revoked(
        &self,
        keys: &[(String, String)],
    ) -> Result<Vec<String>, HostedIssuerError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let kids: Vec<_> = keys.iter().map(|(kid, _)| kid.clone()).collect();
        let hashes: Vec<_> = keys
            .iter()
            .map(|(_, material)| material_hash(material))
            .collect();
        let rows = static_key_revocations::Entity::find()
            .filter(
                Condition::any()
                    .add(static_key_revocations::Column::Kid.is_in(kids))
                    .add(static_key_revocations::Column::Material.is_in(hashes)),
            )
            .all(self.store.current().as_ref())
            .await
            .map_err(find_err)?;
        let revoked_kids: HashSet<_> = rows.iter().map(|row| row.kid.as_str()).collect();
        let revoked_materials: HashSet<_> = rows.iter().map(|row| row.material.as_str()).collect();
        Ok(keys
            .iter()
            .filter(|(kid, material)| {
                let hash = material_hash(material);
                revoked_kids.contains(kid.as_str()) || revoked_materials.contains(hash.as_str())
            })
            .map(|(kid, _)| kid.clone())
            .collect())
    }

    async fn list_issuers_after(
        &self,
        after: Option<&str>,
        limit: usize,
        filters: &HostedIssuerFilter,
        now: OffsetDateTime,
    ) -> Result<Vec<HostedIssuer>, HostedIssuerError> {
        let db = self.store.current();
        let mut query = issuers::Entity::find()
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .order_by(
                bytewise_text_order("issuers.issuer", db.get_database_backend()),
                Order::Asc,
            )
            .limit(limit as u64);
        if let Some(after) = after {
            query = query.filter(bytewise_text_after(
                "issuers.issuer",
                after,
                db.get_database_backend(),
            ));
        }
        if let Some(tier) = &filters.tier {
            query = query.filter(issuers::Column::Tier.eq(tier));
        }
        if let Some(owner) = &filters.owner {
            query = query.filter(exact_text_eq(
                "issuers.owner",
                owner,
                db.get_database_backend(),
            ));
        }
        let unexpired = Condition::any()
            .add(issuers::Column::ExpiresAt.is_null())
            .add(issuers::Column::ExpiresAt.gt(now.unix_timestamp()));
        query = match filters.state {
            Some(HostedIssuerReadState::Suspended) => query.filter(
                Condition::any()
                    .add(issuers::Column::State.eq(HostedIssuerState::Suspended.as_str()))
                    .add(issuers::Column::State.eq("disabled")),
            ),
            Some(HostedIssuerReadState::Expired) => query
                .filter(issuers::Column::State.eq(HostedIssuerState::Active.as_str()))
                .filter(issuers::Column::ExpiresAt.lte(now.unix_timestamp())),
            Some(HostedIssuerReadState::Active) => query
                .filter(issuers::Column::State.eq(HostedIssuerState::Active.as_str()))
                .filter(unexpired),
            None => query,
        };
        query
            .all(self.store.current().as_ref())
            .await
            .map_err(find_err)?
            .into_iter()
            .map(parse_issuer)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn issuer_keys(
        &self,
        issuer_id: &str,
    ) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
        hosted_issuer_keys::Entity::find()
            .filter(hosted_issuer_keys::Column::IssuerId.eq(issuer_id))
            .order_by_desc(hosted_issuer_keys::Column::CreatedAt)
            .order_by_asc(hosted_issuer_keys::Column::Kid)
            .all(self.store.current().as_ref())
            .await
            .map_err(find_err)?
            .into_iter()
            .map(parse_key)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn issuer_keys_for(
        &self,
        issuer_ids: &[String],
    ) -> Result<HashMap<String, Vec<HostedIssuerKey>>, HostedIssuerError> {
        if issuer_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let keys = hosted_issuer_keys::Entity::find()
            .filter(hosted_issuer_keys::Column::IssuerId.is_in(issuer_ids.iter().cloned()))
            .order_by_asc(hosted_issuer_keys::Column::IssuerId)
            .order_by_desc(hosted_issuer_keys::Column::CreatedAt)
            .order_by_asc(hosted_issuer_keys::Column::Kid)
            .all(self.store.current().as_ref())
            .await
            .map_err(find_err)?;
        let mut grouped: HashMap<String, Vec<HostedIssuerKey>> = HashMap::new();
        for row in keys {
            let issuer_id = row.issuer_id.clone();
            grouped.entry(issuer_id).or_default().push(parse_key(row)?);
        }
        Ok(grouped)
    }

    async fn find_key_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<HostedIssuerKeyEntry>, HostedIssuerError> {
        self.store.find_entry_by_kid(kid).await.map_err(Into::into)
    }

    async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
        load_issuer(id, self.store.current().as_ref())
            .await
            .map_err(Into::into)
    }

    async fn create_issuer(
        &self,
        issuer: HostedIssuer,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        self.store
            .create_issuer_unit(issuer, actor)
            .await
            .map_err(Into::into)
    }

    async fn create_issuer_with_key(
        &self,
        mut issuer: HostedIssuer,
        key: HostedIssuerKey,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        if key.issuer_id != issuer.id {
            return Err(HostedIssuerError::InvalidPublicJwk(
                "key metadata does not match its issuer".into(),
            ));
        }
        validate_key_window(&key).map_err(hosted_error)?;
        let value: serde_json::Value = serde_json::from_slice(key.jwk.as_bytes())
            .map_err(|e| HostedIssuerError::InvalidPublicJwk(e.to_string()))?;
        let material =
            canonical_jwk_material(&value).map_err(HostedIssuerError::InvalidPublicJwk)?;
        time_query("insert", "hosted_issuer", async {
        let db = self.store.current();
        for attempt in 0..AGGREGATION_ID_RETRIES {
            if attempt > 0 {
                issuer.aggregation_id = AggregationId::generate();
            }
            let txn = begin_read_committed(&db).await.map_err(err_txn)?;
            if let Err(e) = insert_issuer_row(&txn, &issuer).await {
                let classified = classify_after_rollback(txn, e, "hosted issuer insert").await;
                if matches!(classified, RepositoryError::DuplicateEntry)
                    && load_issuer(&issuer.id, db.as_ref())
                        .await
                        .map_err(HostedIssuerError::from)?
                        .is_none()
                {
                    continue;
                }
                return Err(classified.into());
            }
            let key_hash = material_hash(&material);
            if let Err(e) = time_query("insert", "issuer_key", insert_key_row(&txn, &key, &key_hash)).await {
                let classified = classify_after_rollback(txn, e, "initial key insert").await;
                if matches!(classified, RepositoryError::DuplicateEntry) {
                    if load_entry(&key.kid, &db).await.map_err(HostedIssuerError::from)?.is_some() {
                        return Err(HostedIssuerError::AlreadyExists);
                    }
                    if let Some(blocker) = find_key_by_material_hash(&material_hash(&material), &db)
                        .await
                        .map_err(HostedIssuerError::from)?
                    {
                        tracing::warn!(
                            kid = %key.kid,
                            owner = %blocker.issuer_id,
                            "rejecting a hosted key whose material is already registered"
                        );
                        return Err(HostedIssuerError::KeyMaterialReused);
                    }
                }
                return Err(classified.into());
            }
            for (action, after) in [
                (
                    "issuer.created",
                    serde_json::json!({"state": "active", "version": 1, "aggregation_id": issuer.aggregation_id.0}),
                ),
                (
                    "key.registered",
                    serde_json::json!({"kid": key.kid, "state": key.state.as_str(), "version": issuer.version}),
                ),
            ] {
                if let Err(e) =
                    append_lifecycle_audit(&txn, &issuer.id, actor, action, None, Some(after)).await
                {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::Backend(Box::new(e)));
                }
            }
            txn.commit().await.map_err(err_txn)?;
            issuer.created_at =
                OffsetDateTime::from_unix_timestamp(issuer.created_at.unix_timestamp())
                    .expect("persisted timestamp is valid");
            issuer.expires_at = issuer.expires_at.map(|v| {
                OffsetDateTime::from_unix_timestamp(v.unix_timestamp())
                    .expect("persisted timestamp is valid")
            });
            return Ok(issuer);
        }
        Err(HostedIssuerError::AlreadyExists)
        }).await
    }

    async fn add_key(&self, key: HostedIssuerKey, actor: &str) -> Result<(), HostedIssuerError> {
        self.store
            .add_key_if_version(key, None, self.key_limits.as_deref(), actor)
            .await
            .map_err(hosted_error)
    }

    async fn add_key_if_version(
        &self,
        key: HostedIssuerKey,
        expected_version: u64,
        actor: &str,
    ) -> Result<(), HostedIssuerError> {
        self.store
            .add_key_if_version(
                key,
                Some(expected_version),
                self.key_limits.as_deref(),
                actor,
            )
            .await
            .map_err(hosted_error)
    }

    async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
        self.store.all_keys().await.map_err(Into::into)
    }

    async fn all_issuers(&self) -> Result<Vec<HostedIssuer>, HostedIssuerError> {
        self.store.all_issuers().await.map_err(Into::into)
    }

    async fn find_key_by_material(
        &self,
        material: &str,
    ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
        self.store
            .find_key_by_material(material)
            .await
            .map_err(Into::into)
    }

    async fn find_issuer_ids(&self, ids: &[String]) -> Result<HashSet<String>, HostedIssuerError> {
        self.store.find_issuer_ids(ids).await.map_err(Into::into)
    }
}

async fn append_lifecycle_audit(
    txn: &sea_orm::DatabaseTransaction,
    issuer_id: &str,
    actor: &str,
    action: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Result<(), DbErr> {
    issuer_audit_events::Entity::insert(issuer_audit_events::ActiveModel {
        // UUIDv7 orders lexically by millisecond, so the audit trail has a
        // real event order even though `created_at` only has whole seconds.
        id: Set(uuid::Uuid::now_v7().to_string()),
        issuer_id: Set(Some(issuer_id.to_owned())),
        actor: Set(Some(actor.to_owned())),
        action: Set(action.to_owned()),
        before: Set(before),
        after: Set(after),
        created_at: Set(OffsetDateTime::now_utc().unix_timestamp()),
    })
    .exec_without_returning(txn)
    .await
    .map(|_| ())
}

#[async_trait]
impl HostedIssuerLifecycleStore for SqlHostedIssuerStore {
    async fn get_issuer(&self, issuer_id: &str) -> Result<HostedIssuer, HostedIssuerError> {
        self.find_issuer(issuer_id)
            .await?
            .ok_or(HostedIssuerError::NotFound)
    }

    async fn set_issuer_state(
        &self,
        issuer_id: &str,
        state: HostedIssuerState,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        // Decision rules (reactivation after expiry, no-op detection) live in
        // `HostedIssuerLifecycleService`; this method only enforces the
        // optimistic version guard and commits the change with its audit
        // event in one transaction.
        let db = self.store.current();
        let txn = begin_read_committed(&db).await.map_err(err_txn)?;
        let row = match issuers::Entity::find()
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .one(&txn)
            .await
        {
            Ok(row) => {
                let Some(row) = row else {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::NotFound);
                };
                row
            }
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        let previous = match parse_issuer(row.clone()) {
            Ok(previous) => previous,
            Err(e) => {
                rollback_quietly(txn).await;
                return Err(e.into());
            }
        };
        if previous.version != expected_version {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::VersionMismatch);
        }
        if previous.state == state {
            // A concurrent request applied the same state; report it unchanged.
            txn.commit().await.map_err(err_txn)?;
            return Ok(previous);
        }
        let Some(next_version) = row.version.checked_add(1) else {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "issuer version overflow",
            ))));
        };
        let changed = match issuers::Entity::update_many()
            .col_expr(issuers::Column::State, Expr::value(state.as_str()))
            .col_expr(issuers::Column::Version, Expr::value(next_version))
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .filter(issuers::Column::Version.eq(expected_version as i64))
            .exec(&txn)
            .await
        {
            Ok(changed) => changed,
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        if changed.rows_affected != 1 {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::VersionMismatch);
        }
        if let Err(e) = append_lifecycle_audit(
            &txn,
            issuer_id,
            actor,
            "issuer.state_changed",
            Some(serde_json::json!({"state": row.state, "version": row.version})),
            Some(serde_json::json!({"state": state.as_str(), "version": next_version})),
        )
        .await
        {
            let classified = err_txn(e);
            rollback_quietly(txn).await;
            return Err(classified.into());
        }
        txn.commit().await.map_err(err_txn)?;
        Ok(HostedIssuer {
            state,
            version: next_version as u64,
            ..previous
        })
    }

    async fn set_issuer_expiry(
        &self,
        issuer_id: &str,
        expires_at: OffsetDateTime,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuer, HostedIssuerError> {
        let db = self.store.current();
        let txn = begin_read_committed(&db).await.map_err(err_txn)?;
        let row = issuers::Entity::find()
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .one(&txn)
            .await
            .map_err(err_txn)?
            .ok_or(HostedIssuerError::NotFound)?;
        let previous = parse_issuer(row.clone()).map_err(HostedIssuerError::from)?;
        if previous.version != expected_version {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::VersionMismatch);
        }
        if previous
            .expires_at
            .is_some_and(|v| v.unix_timestamp() == expires_at.unix_timestamp())
        {
            txn.commit().await.map_err(err_txn)?;
            return Ok(previous);
        }
        let next_version = row.version.checked_add(1).ok_or_else(|| {
            HostedIssuerError::Backend(Box::new(std::io::Error::other("issuer version overflow")))
        })?;
        let changed = issuers::Entity::update_many()
            .col_expr(
                issuers::Column::ExpiresAt,
                Expr::value(expires_at.unix_timestamp()),
            )
            .col_expr(issuers::Column::Version, Expr::value(next_version))
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .filter(issuers::Column::Version.eq(row.version))
            .exec(&txn)
            .await
            .map_err(err_txn)?;
        if changed.rows_affected != 1 {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::VersionMismatch);
        }
        append_lifecycle_audit(
            &txn, issuer_id, actor, "issuer.expiry_changed",
            Some(serde_json::json!({"expires_at": row.expires_at, "version": row.version})),
            Some(serde_json::json!({"expires_at": expires_at.unix_timestamp(), "version": next_version})),
        ).await.map_err(err_txn)?;
        txn.commit().await.map_err(err_txn)?;
        Ok(HostedIssuer {
            expires_at: Some(
                OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp())
                    .expect("persisted timestamp is valid"),
            ),
            version: next_version as u64,
            ..previous
        })
    }

    async fn revoke_key(
        &self,
        issuer_id: &str,
        kid: &str,
        expected_version: u64,
        actor: &str,
    ) -> Result<HostedIssuerKey, HostedIssuerError> {
        let db = self.store.current();
        let txn = begin_read_committed(&db).await.map_err(err_txn)?;
        let row = match hosted_issuer_keys::Entity::find_by_id(kid)
            .filter(exact_text_eq(
                "issuer_keys.issuer_id",
                issuer_id,
                db.get_database_backend(),
            ))
            .one(&txn)
            .await
        {
            Ok(row) => {
                let Some(row) = row else {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::NotFound);
                };
                row
            }
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        let owner = match issuers::Entity::find()
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .one(&txn)
            .await
        {
            Ok(owner) => {
                let Some(owner) = owner else {
                    rollback_quietly(txn).await;
                    return Err(HostedIssuerError::NotFound);
                };
                owner
            }
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        let previous = match parse_key(row.clone()) {
            Ok(previous) => previous,
            Err(e) => {
                rollback_quietly(txn).await;
                return Err(e.into());
            }
        };
        if previous.state == HostedIssuerKeyState::Revoked {
            txn.commit().await.map_err(err_txn)?;
            return Ok(previous);
        }
        if owner.version != i64::try_from(expected_version).unwrap_or(-1) {
            rollback_quietly(txn).await;
            return revoked_key_after_rollback(db.as_ref(), issuer_id, kid).await;
        }
        let Some(next_version) = owner.version.checked_add(1) else {
            rollback_quietly(txn).await;
            return Err(HostedIssuerError::Backend(Box::new(std::io::Error::other(
                "issuer version overflow",
            ))));
        };
        let version_changed = match issuers::Entity::update_many()
            .col_expr(issuers::Column::Version, Expr::value(next_version))
            .filter(exact_text_eq(
                "issuers.issuer",
                issuer_id,
                db.get_database_backend(),
            ))
            .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
            .filter(issuers::Column::Version.eq(owner.version))
            .exec(&txn)
            .await
        {
            Ok(changed) => changed,
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        if version_changed.rows_affected != 1 {
            rollback_quietly(txn).await;
            return revoked_key_after_rollback(db.as_ref(), issuer_id, kid).await;
        }
        let changed = match hosted_issuer_keys::Entity::update_many()
            .col_expr(hosted_issuer_keys::Column::State, Expr::value("revoked"))
            .filter(hosted_issuer_keys::Column::Kid.eq(kid))
            .filter(hosted_issuer_keys::Column::IssuerId.eq(issuer_id))
            .filter(hosted_issuer_keys::Column::State.eq(row.state.as_str()))
            .exec(&txn)
            .await
        {
            Ok(changed) => changed,
            Err(e) => {
                let classified = err_txn(e);
                rollback_quietly(txn).await;
                return Err(classified.into());
            }
        };
        if changed.rows_affected != 1 {
            rollback_quietly(txn).await;
            return revoked_key_after_rollback(db.as_ref(), issuer_id, kid).await;
        }
        if let Err(e) = append_lifecycle_audit(
            &txn,
            issuer_id,
            actor,
            "key.revoked",
            Some(serde_json::json!({"kid": kid, "state": row.state, "version": owner.version})),
            Some(serde_json::json!({"kid": kid, "state": "revoked", "version": next_version})),
        )
        .await
        {
            let classified = err_txn(e);
            rollback_quietly(txn).await;
            return Err(classified.into());
        }
        txn.commit().await.map_err(err_txn)?;
        Ok(HostedIssuerKey {
            state: HostedIssuerKeyState::Revoked,
            ..previous
        })
    }
}

impl From<RepositoryError> for HostedIssuerError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::DuplicateEntry => HostedIssuerError::AlreadyExists,
            RepositoryError::NotFound => HostedIssuerError::NotFound,
            RepositoryError::Contention { code } => HostedIssuerError::Contention { code },
            RepositoryError::Unavailable => HostedIssuerError::Unavailable,
            RepositoryError::DataError(message) => HostedIssuerError::Corrupt(message),
            other => HostedIssuerError::Backend(Box::new(other)),
        }
    }
}

use crate::domain::models::credential::CredentialError;

impl From<CredentialError> for HostedIssuerError {
    fn from(value: CredentialError) -> Self {
        match value {
            CredentialError::InvalidPublicJwk(message) => {
                HostedIssuerError::InvalidPublicJwk(message)
            }
            CredentialError::AlreadyExists => HostedIssuerError::AlreadyExists,
            CredentialError::Contention { code } => HostedIssuerError::Contention { code },
            CredentialError::Backend(error) => HostedIssuerError::Backend(error),
        }
    }
}
