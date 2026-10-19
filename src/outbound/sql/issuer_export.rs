//! Read-only migration of legacy database credentials to the trust registry.

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement};
use thiserror::Error;

use crate::server::auth::issuer_registry::{IssuerRegistry, RegistryError};

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("read legacy credentials: {0}")]
    Database(#[from] DbErr),
    #[error("cannot export issuer `{issuer}`: {reason}")]
    InvalidIssuer { issuer: String, reason: String },
    #[error("exported registry is invalid: {0}")]
    Registry(#[from] RegistryError),
    #[error("serialize registry: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Export a validated draft without migrating or modifying the source database.
/// Missing aggregation IDs are rejected: inventing one could break published URIs.
pub async fn export_issuers(db: &DatabaseConnection) -> Result<String, ExportError> {
    let rows = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT issuer, public_key, aggregation_id FROM credentials ORDER BY issuer",
        ))
        .await?;
    let mut issuers = Vec::with_capacity(rows.len());
    for row in rows {
        let issuer: String = row.try_get("", "issuer")?;
        let invalid = |reason: String| ExportError::InvalidIssuer {
            issuer: issuer.clone(),
            reason,
        };
        let aggregation_id: Option<String> = row.try_get("", "aggregation_id")?;
        let aggregation_id = aggregation_id.ok_or_else(|| {
            invalid(
                "missing aggregation_id; resolve it with the running server before exporting"
                    .into(),
            )
        })?;
        let mut jwk: serde_json::Value = row.try_get("", "public_key")?;
        // Older rows can predate alg/kid. Infer only unambiguous supported algorithms.
        let alg = jwk
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
                (Some("EC"), Some("P-256")) => Some("ES256".into()),
                (Some("EC"), Some("P-384")) => Some("ES384".into()),
                (Some("OKP"), Some("Ed25519")) => Some("EdDSA".into()),
                (Some("RSA"), _) => Some("PS256".into()),
                _ => None,
            })
            .ok_or_else(|| invalid("unsupported key type or curve".into()))?;
        let parsed: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(jwk.clone()).map_err(|error| invalid(error.to_string()))?;
        let kid = parsed
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .map_err(|error| invalid(error.to_string()))?;
        // Replace legacy metadata in the draft only. Both metadata locations must agree.
        jwk["kid"] = kid.clone().into();
        jwk["alg"] = alg.clone().into();
        issuers.push(serde_json::json!({
            "id": issuer, "aggregation_id": aggregation_id,
            "keys": [{"kid": kid, "alg": alg, "jwk": jwk}],
        }));
    }
    let content = serde_yaml::to_string(&serde_json::json!({
        "version": 1, "issuers": issuers, "admins": [],
    }))?;
    IssuerRegistry::from_yaml(&content)?;
    Ok(content)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use sea_orm::{Database, DatabaseBackend};

    async fn legacy_database(aggregation: Option<&str>, private: bool) -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite,
            "CREATE TABLE credentials (issuer TEXT PRIMARY KEY, public_key JSON NOT NULL, aggregation_id TEXT)"))
            .await.unwrap();
        let mut key: serde_json::Value =
            serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        key.as_object_mut().unwrap().remove("kid");
        key.as_object_mut().unwrap().remove("alg");
        if private {
            key["d"] = "secret".into();
        }
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO credentials VALUES (?, ?, ?)",
            vec![
                "legacy-issuer".into(),
                key.into(),
                aggregation.map(str::to_owned).into(),
            ],
        ))
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn legacy_keys_get_rfc7638_thumbprints_without_database_writes() {
        let id = "11111111-1111-4111-8111-111111111111";
        let db = legacy_database(Some(id), false).await;
        let exported = export_issuers(&db).await.unwrap();
        let registry = IssuerRegistry::from_yaml(&exported).unwrap();
        let entry = registry.issuer("legacy-issuer").unwrap();
        assert_eq!(entry.aggregation_id.to_string(), id);
        let original: jsonwebtoken::jwk::Jwk =
            serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        assert_eq!(
            entry.keys[0].kid,
            original
                .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
                .unwrap()
        );
        assert_eq!(entry.keys[0].alg, "ES256");
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT public_key FROM credentials",
            ))
            .await
            .unwrap()
            .unwrap();
        let original: serde_json::Value = row.try_get("", "public_key").unwrap();
        assert!(original.get("kid").is_none());
        assert!(original.get("alg").is_none());
    }

    #[tokio::test]
    async fn refuses_to_invent_aggregation_ids_or_export_private_keys() {
        let db = legacy_database(None, false).await;
        assert!(matches!(
            export_issuers(&db).await,
            Err(ExportError::InvalidIssuer { .. })
        ));
        let db = legacy_database(Some("11111111-1111-4111-8111-111111111111"), true).await;
        assert!(matches!(
            export_issuers(&db).await,
            Err(ExportError::Registry(_))
        ));
    }
}
