//! SQL adapter for the hosted-profile issuer store (`issuers`, `issuer_keys`),
//! plus the `issuer_aggregations` mapping every hosted creation records in the
//! same transaction. Dynamic keys resolve per request by `kid` primary key
//! with no cache, so revocation takes effect on the next request.

use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, QueryFilter, QuerySelect, Set, sea_query::OnConflict,
};
use std::sync::Arc;
use time::OffsetDateTime;

use super::error::{RepositoryError, contention_err};
use super::models::{PublicKey, hosted_issuer_keys, hosted_issuers, issuer_aggregations};
use super::store::{SeaOrmStore, SwappableDatabaseConnection, begin_read_committed};
use crate::domain::models::credential::{AggregationId, PublicJwk, canonical_jwk_material};
use crate::domain::models::hosted_issuer::{
    HostedIssuer, HostedIssuerError, HostedIssuerKey, HostedIssuerKeyEntry, HostedIssuerKeyState,
    HostedIssuerState,
};
use crate::domain::ports::HostedIssuerStore;
use crate::utils::metrics_db::time_query;

/// How often a creation regenerates a colliding random aggregation ID. 128
/// random bits colliding inside one deployment is a fault threshold, not a
/// loop bound.
const AGGREGATION_ID_RETRIES: u32 = 3;

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

fn parse_issuer(
    row: hosted_issuers::Model,
    aggregation_id: AggregationId,
) -> Result<HostedIssuer, RepositoryError> {
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
                row.id
            )));
        }
    };
    Ok(HostedIssuer {
        id: row.id,
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
    issuer: hosted_issuers::Model,
    aggregation_id: AggregationId,
    key: hosted_issuer_keys::Model,
) -> Result<HostedIssuerKeyEntry, RepositoryError> {
    Ok(HostedIssuerKeyEntry {
        issuer: parse_issuer(issuer, aggregation_id)?,
        key: parse_key(key)?,
    })
}

/// The fill-in for a corrupted or host-error `not_before`-style failure is
/// deliberately missing: malformed stored timestamps surface as FindError and
/// fail closed.
///
/// Reads must join three tables: `issuer_keys.kid`, its `issuers` row, and the
/// `issuer_aggregations` mapping created with the issuer. An orphaned row is a
/// data fault (the FK only covers the first hop), not an empty result.
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
    let issuer = hosted_issuers::Entity::find_by_id(&key.issuer_id)
        .one(db)
        .await
        .map_err(find_err)?
        .ok_or_else(|| {
            RepositoryError::FindError(format!("issuer key `{kid}` has no issuer row"))
        })?;
    let mapping = issuer_aggregations::Entity::find_by_id(&issuer.id)
        .one(db)
        .await
        .map_err(find_err)?
        .ok_or_else(|| {
            RepositoryError::FindError(format!(
                "hosted issuer `{}` has no aggregation mapping",
                issuer.id
            ))
        })?;
    let aggregation_id = mapping
        .aggregation_id
        .parse()
        .map(AggregationId)
        .map_err(|e| RepositoryError::FindError(e.to_string()))?;
    Some(parse_entry(issuer, aggregation_id, key)).transpose()
}

async fn load_issuer(
    id: &str,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<HostedIssuer>, RepositoryError> {
    let issuer = hosted_issuers::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(find_err)?;
    let Some(issuer) = issuer else {
        return Ok(None);
    };
    let mapping = issuer_aggregations::Entity::find_by_id(issuer.id.as_str())
        .one(db)
        .await
        .map_err(find_err)?
        .ok_or_else(|| {
            RepositoryError::FindError(format!("hosted issuer `{id}` has no aggregation mapping"))
        })?;
    let aggregation_id = mapping
        .aggregation_id
        .parse()
        .map(AggregationId)
        .map_err(|e| RepositoryError::FindError(e.to_string()))?;
    Some(parse_issuer(issuer, aggregation_id)).transpose()
}

async fn insert_issuer_row(
    txn: &sea_orm::DatabaseTransaction,
    issuer: &HostedIssuer,
) -> Result<(), DbErr> {
    hosted_issuers::Entity::insert(hosted_issuers::ActiveModel {
        id: Set(issuer.id.clone()),
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

/// Same insert–readback discipline as the registry reconciliation
/// (`record_registry_aggregation_ids`): the mapping is only accepted when both
/// directions of the association still name this issuer, so a hosted creation
/// can neither reach an existing mapping nor let two issuers share one.
async fn insert_aggregation_mapping(
    txn: &sea_orm::DatabaseTransaction,
    issuer: &str,
    aggregation_id: &AggregationId,
) -> Result<(), DbErr> {
    let id = aggregation_id.to_string();
    issuer_aggregations::Entity::insert(issuer_aggregations::ActiveModel {
        issuer: Set(issuer.to_string()),
        aggregation_id: Set(id.clone()),
    })
    .on_conflict(
        OnConflict::column(issuer_aggregations::Column::Issuer)
            .do_nothing_on([issuer_aggregations::Column::Issuer])
            .to_owned(),
    )
    .exec_without_returning(txn)
    .await?;
    let by_issuer = issuer_aggregations::Entity::find_by_id(issuer)
        .one(txn)
        .await?;
    let by_id = issuer_aggregations::Entity::find()
        .filter(issuer_aggregations::Column::AggregationId.eq(&id))
        .one(txn)
        .await?;
    match (by_issuer, by_id) {
        (Some(issuer_row), Some(id_row))
            if issuer_row.aggregation_id == id && id_row.issuer == issuer =>
        {
            Ok(())
        }
        // A colliding caller won the race for this aggregation ID: the stored
        // direction of the association names someone else.
        (Some(_), Some(id_row)) if id_row.issuer != issuer => Err(DbErr::Custom(format!(
            "aggregation mapping conflict for issuer {issuer}"
        ))),
        _ => Err(DbErr::Custom(format!(
            "aggregation mapping lookup failed for issuer {issuer}"
        ))),
    }
}

/// Returns the issuer owning the colliding material, if any. An exact
/// re-registration (same issuer, same kid) is skipped: its row insert turns
/// into the client-visible duplicate-key conflict instead.
async fn find_colliding_material(
    material: &str,
    key: &HostedIssuerKey,
    db: &sea_orm::DatabaseConnection,
) -> Result<Option<String>, RepositoryError> {
    let rows = hosted_issuer_keys::Entity::find()
        .all(db)
        .await
        .map_err(find_err)?;
    for row in rows {
        if row.kid == key.kid && row.issuer_id == key.issuer_id {
            continue;
        }
        let bytes = serde_json::to_vec(&row.jwk).map_err(|e| {
            RepositoryError::FindError(format!("stored hosted JWK serialization: {e}"))
        })?;
        // Malformed material cannot exist through validated writes, but an old
        // pod or manual edit still must not silently defeat the check.
        let existing = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| canonical_jwk_material(&value).ok());
        match existing {
            Some(existing) if existing == material => return Ok(Some(row.issuer_id)),
            Some(_) => continue,
            None => {
                return Err(RepositoryError::FindError(format!(
                    "stored issuer key `{}` has malformed JWK parameters",
                    row.kid
                )));
            }
        }
    }
    Ok(None)
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
                if let Err(insert_err) = insert_issuer_row(&txn, &stored).await {
                    return Err(
                        classify_after_rollback(txn, insert_err, "hosted issuer insert").await,
                    );
                }
                let mapping_result =
                    insert_aggregation_mapping(&txn, &stored.id, &stored.aggregation_id).await;
                if let Err(mapping_err) = mapping_result {
                    // Only a lost race for the random aggregation ID is
                    // retried with a fresh ID; anything else fails the write.
                    if aggregation_mapping_conflict(&mapping_err) {
                        txn.rollback().await.ok();
                        continue;
                    }
                    return Err(
                        classify_after_rollback(txn, mapping_err, "hosted issuer mapping").await,
                    );
                }
                txn.commit().await.map_err(map_insert_err)?;
                return Ok(stored);
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
        time_query("insert", "issuer_key", async {
            let material = serde_json::from_slice::<serde_json::Value>(key.jwk.as_bytes())
                .map_err(|err| RepositoryError::InsertError(err.to_string()))
                .and_then(|value| canonical_jwk_material(&value).map_err(err_jwk))?;
            let db = self.current();
            if let Some(reused_by) = find_colliding_material(&material, &key, &db).await? {
                return Err(RepositoryError::InsertError(format!(
                    "key material reused by issuer {reused_by}"
                )));
            }
            let txn = begin_read_committed(&db).await.map_err(insert_first_err)?;
            if hosted_issuers::Entity::find_by_id(&key.issuer_id)
                .select_only()
                .column(hosted_issuers::Column::Id)
                .into_tuple::<String>()
                .one(&txn)
                .await
                .map_err(err_txn)?
                .is_none()
            {
                return Err(RepositoryError::InsertError(format!(
                    "issuer `{}` has no row to attach a key to",
                    key.issuer_id
                )));
            }
            if let Err(insert_err) =
                hosted_issuer_keys::Entity::insert(hosted_issuer_keys::ActiveModel {
                    kid: Set(key.kid.clone()),
                    issuer_id: Set(key.issuer_id.clone()),
                    alg: Set(format!("{:?}", key.jwk.algorithm())),
                    jwk: Set(PublicKey::from(key.jwk.jwk().clone())),
                    state: Set(HostedIssuerKeyState::Active.as_str().to_string()),
                    not_before: Set(key.not_before.map(|value| value.unix_timestamp())),
                    not_after: Set(key.not_after.map(|value| value.unix_timestamp())),
                    created_at: Set(key.created_at.unix_timestamp()),
                })
                .exec_without_returning(&txn)
                .await
            {
                return Err(classify_after_rollback(txn, insert_err, "issuer key insert").await);
            }
            txn.commit().await.map_err(map_insert_err)?;
            Ok(())
        })
        .await
    }

    async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, RepositoryError> {
        time_query("find_all", "issuer_key", async {
            let rows = hosted_issuer_keys::Entity::find()
                .all(self.current().as_ref())
                .await
                .map_err(find_err)?;
            rows.into_iter().map(parse_key).collect()
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

/// Untagged driver errors cannot be reopened, so the mapping readback mirrors
/// its own decision: the sentinel is produced only where the stored direction
/// of the association already names someone else.
fn aggregation_mapping_conflict(err: &DbErr) -> bool {
    matches!(
        err,
        DbErr::Custom(message) if message.starts_with("aggregation mapping conflict")
    )
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
