//! SQL adapter for the hosted-profile issuer store. A portal issuer is a
//! row of the shared ownership table (`issuers`, expanded by the
//! `hosted_issuers` migration), so creating one records its aggregation ID
//! and its ownership/quota slot in the same unit; keys live in
//! `issuer_keys`. Dynamic keys resolve per request by `kid` primary key
//! with no cache, so revocation takes effect on the next request.

use async_trait::async_trait;
use sea_orm::{ColumnTrait, DbErr, EntityTrait, QueryFilter, QuerySelect, Set};
use std::sync::Arc;
use time::OffsetDateTime;

use super::error::{RepositoryError, contention_err};
use super::models::{PublicKey, hosted_issuer_keys, issuers};
use super::store::{SeaOrmStore, SwappableDatabaseConnection, begin_read_committed};
use crate::domain::models::credential::{AggregationId, PublicJwk, canonical_jwk_material};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerKey, HostedIssuerKeyEntry, HostedIssuerKeyState,
    HostedIssuerState,
};
use crate::domain::ports::HostedIssuerStore;
use crate::utils::metrics_db::time_query;

/// How often a creation regenerates a colliding random aggregation ID. 122
/// random bits colliding inside one deployment is a fault threshold, not a
/// loop bound.
const AGGREGATION_ID_RETRIES: u32 = 3;

/// The `source` value marking a row as a hosted-profile (portal) issuer. Rows
/// written by the registry or credential paths carry the migration default and
/// must never be treated as hosted.
const PORTAL_SOURCE: &str = "portal";

#[derive(Clone)]
pub(crate) enum HostedIssuerRow {}

#[derive(Clone)]
pub struct SqlHostedIssuerStore {
    store: SeaOrmStore<HostedIssuerRow>,
}

impl SqlHostedIssuerStore {
    pub fn new(db: Arc<sea_orm::DatabaseConnection>) -> Self {
        Self {
            store: SeaOrmStore::new(db),
        }
    }

    pub fn from_handle(db: Arc<SwappableDatabaseConnection>) -> Self {
        Self {
            store: SeaOrmStore::from_handle(db),
        }
    }
}

fn map_insert_err(e: DbErr) -> RepositoryError {
    match e.sql_err() {
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_)) => RepositoryError::DuplicateEntry,
        _ => contention_err(&e).unwrap_or_else(|| RepositoryError::InsertError(e.to_string())),
    }
}

fn find_err(e: DbErr) -> RepositoryError {
    RepositoryError::FindError(e.to_string())
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

fn tried_from_unix(seconds: i64) -> Result<OffsetDateTime, RepositoryError> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|e| RepositoryError::FindError(e.to_string()))
}

/// A hosted `issuers` row must carry its aggregation ID and a source of
/// `portal`: metadata added by the hosted migration that another trust
/// source leaves defaulted. A row without the mapping cannot resolve, so
/// aggregation-less registry rows stay unreachable through this adapter.
fn parse_issuer(row: issuers::Model) -> Result<HostedIssuer, RepositoryError> {
    let aggregation_id = match row.aggregation_id.as_deref().map(str::parse) {
        Some(Ok(uuid)) => AggregationId(uuid),
        Some(Err(e)) => {
            return Err(RepositoryError::FindError(format!(
                "hosted issuer `{}` has an unusable aggregation mapping: {e}",
                row.issuer
            )));
        }
        None => {
            return Err(RepositoryError::FindError(format!(
                "hosted issuer `{}` has no aggregation mapping",
                row.issuer
            )));
        }
    };
    let created_at = tried_from_unix(row.created_at)?;
    let expires_at = match row.expires_at {
        Some(seconds) => Some(tried_from_unix(seconds)?),
        None => None,
    };
    let state = match row.state.as_str() {
        value if value == HostedIssuerState::Active.as_str() => HostedIssuerState::Active,
        value if value == HostedIssuerState::Disabled.as_str() => HostedIssuerState::Disabled,
        other => {
            return Err(RepositoryError::FindError(format!(
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
        Some(seconds) => Some(tried_from_unix(seconds)?),
        None => None,
    };
    let not_after = match row.not_after {
        Some(seconds) => Some(tried_from_unix(seconds)?),
        None => None,
    };
    let state = match row.state.as_str() {
        value if value == HostedIssuerKeyState::Active.as_str() => HostedIssuerKeyState::Active,
        value if value == HostedIssuerKeyState::Revoked.as_str() => HostedIssuerKeyState::Revoked,
        other => {
            return Err(RepositoryError::FindError(format!(
                "issuer key `{}` has unknown state `{other}`",
                row.kid
            )));
        }
    };
    let bytes = serde_json::to_vec(&row.jwk)
        .map_err(|e| RepositoryError::FindError(format!("stored hosted JWK serialization: {e}")))?;
    Ok(HostedIssuerKey {
        kid: row.kid,
        issuer_id: row.issuer_id,
        jwk: PublicJwk::try_new(bytes).map_err(|e| RepositoryError::FindError(e.to_string()))?,
        created_at: tried_from_unix(row.created_at)?,
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

/// The fill-in for a corrupted or host-error `not_before`-style failure is
/// deliberately missing: malformed stored timestamps surface as FindError and
/// fail closed.
///
/// Reads join `issuer_keys.kid` with its `issuers` row. An orphaned row is a
/// data fault (the FK only covers one direction), not an empty result.
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
        .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
        .one(db)
        .await
        .map_err(find_err)?
        .ok_or_else(|| {
            RepositoryError::FindError(format!("issuer key `{kid}` has no issuer row"))
        })?;
    Some(parse_entry(issuer, key)).transpose()
}

async fn load_issuer(
    id: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<HostedIssuer>, RepositoryError> {
    let issuer = issuers::Entity::find_by_id(id)
        .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
        .one(db)
        .await
        .map_err(find_err)?;
    match issuer {
        Some(row) => Ok(Some(parse_issuer(row)?)),
        None => Ok(None),
    }
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

/// The issuer that already owns a key with the given material hash, if any.
async fn find_material_owner(
    hash: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<String>, RepositoryError> {
    let row = hosted_issuer_keys::Entity::find()
        .filter(hosted_issuer_keys::Column::KeyMaterial.eq(hash))
        .one(db)
        .await
        .map_err(find_err)?;
    Ok(row.map(|row| row.issuer_id))
}

impl SeaOrmStore<HostedIssuerRow> {
    #[tracing::instrument(skip(self, issuer), fields(db.system = "sea-orm"))]
    async fn create_issuer_unit(
        &self,
        issuer: HostedIssuer,
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
                        txn.commit().await.map_err(map_insert_err)?;
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

    async fn add_key(&self, key: HostedIssuerKey) -> Result<(), RepositoryError> {
        // The `kid` column is authoritative (the registry keeps the same
        // rule): a key whose embedded `kid` disagrees with its row never
        // enters storage.
        if key.jwk.key_id() != key.kid {
            return Err(RepositoryError::InsertError(format!(
                "key `{}` has conflicting JWK kid metadata",
                key.kid
            )));
        }
        // A permanently invalid window is a config error, not a valid key that
        // happens to be out of range: it can never authenticate.
        if key
            .not_before
            .zip(key.not_after)
            .is_some_and(|(before, after)| before >= after)
        {
            return Err(RepositoryError::InsertError(format!(
                "key `{}` has not_before >= not_after",
                key.kid
            )));
        }
        time_query("insert", "issuer_key", async {
            let material = serde_json::from_slice::<serde_json::Value>(key.jwk.as_bytes())
                .map_err(|err| RepositoryError::InsertError(err.to_string()))
                .and_then(|value| canonical_jwk_material(&value).map_err(err_jwk))?;
            let hash = material_hash(&material);
            let db = self.current();
            let txn = begin_read_committed(&db).await.map_err(insert_first_err)?;
            let issuer_exists = issuers::Entity::find_by_id(&key.issuer_id)
                .filter(issuers::Column::Source.eq(PORTAL_SOURCE))
                .select_only()
                .column(issuers::Column::Issuer)
                .into_tuple::<String>()
                .one(&txn)
                .await
                .map_err(err_txn)?
                .is_some();
            if !issuer_exists {
                txn.rollback().await.ok();
                return Err(RepositoryError::NotFound);
            }
            let insert = hosted_issuer_keys::Entity::insert(hosted_issuer_keys::ActiveModel {
                kid: Set(key.kid.clone()),
                issuer_id: Set(key.issuer_id.clone()),
                key_material: Set(hash),
                alg: Set(jose_alg_name(key.jwk.algorithm()).to_string()),
                jwk: Set(PublicKey::from(key.jwk.jwk().clone())),
                state: Set(key.state.as_str().to_string()),
                not_before: Set(key.not_before.map(|value| value.unix_timestamp())),
                not_after: Set(key.not_after.map(|value| value.unix_timestamp())),
                created_at: Set(key.created_at.unix_timestamp()),
            })
            .exec_without_returning(&txn)
            .await;
            match insert {
                Ok(_) => {
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
                        if let Some(owner) =
                            find_material_owner(&material_hash(&material), &db).await?
                        {
                            return Err(RepositoryError::InsertError(format!(
                                "key material reused by issuer {owner}"
                            )));
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

    async fn find_entry_by_kid(
        &self,
        kid: &str,
    ) -> Result<Option<HostedIssuerKeyEntry>, RepositoryError> {
        time_query("find_by_kid", "issuer_key", async {
            load_entry(kid, self.current().as_ref()).await
        })
        .await
    }
}

/// Untagged driver errors cannot be reopened, so the material-reuse sentinel
/// produced by `add_key` is the one place a client-visible discrimination is
/// recoverable; everything else keeps the shared mapping.
fn hosted_error(err: RepositoryError) -> HostedIssuerError {
    match &err {
        RepositoryError::InsertError(message) => {
            match message.strip_prefix("key material reused by issuer ") {
                Some(issuer_id) => HostedIssuerError::KeyMaterialReused(issuer_id.to_string()),
                None => err.into(),
            }
        }
        _ => err.into(),
    }
}

fn err_txn(e: DbErr) -> RepositoryError {
    RepositoryError::InsertError(e.to_string())
}

fn err_jwk(message: String) -> RepositoryError {
    RepositoryError::InsertError(format!("invalid public JWK: {message}"))
}

fn insert_first_err(e: DbErr) -> RepositoryError {
    RepositoryError::InsertError(format!("hosted write failed to open a transaction: {e}"))
}

#[async_trait]
impl HostedIssuerStore for SqlHostedIssuerStore {
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

    async fn create_issuer(&self, issuer: HostedIssuer) -> Result<HostedIssuer, HostedIssuerError> {
        self.store
            .create_issuer_unit(issuer)
            .await
            .map_err(Into::into)
    }

    async fn add_key(&self, key: HostedIssuerKey) -> Result<(), HostedIssuerError> {
        self.store.add_key(key).await.map_err(hosted_error)
    }

    async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
        self.store.all_keys().await.map_err(Into::into)
    }
}

impl From<RepositoryError> for HostedIssuerError {
    fn from(value: RepositoryError) -> Self {
        match value {
            RepositoryError::DuplicateEntry => HostedIssuerError::AlreadyExists,
            RepositoryError::NotFound => HostedIssuerError::NotFound,
            RepositoryError::Contention { code } => HostedIssuerError::Contention { code },
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
