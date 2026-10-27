use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use sea_orm_migration::SchemaManager;

#[derive(Debug)]
pub struct LegacyIssuerCredential {
    pub issuer: String,
    pub aggregation_id: String,
    pub public_key: serde_json::Value,
}

/// Export every stored issuer credential and its durable aggregation ID as a registry draft.
pub async fn legacy_issuer_credentials(
    db: &DatabaseConnection,
) -> Result<Vec<LegacyIssuerCredential>, Box<dyn std::error::Error + Send + Sync>> {
    let schema = SchemaManager::new(db);
    let has_issuers = schema.has_table("issuers").await?;
    let has_issuer_aggregations = schema.has_table("issuer_aggregations").await?;
    let has_credential_aggregation_id = schema.has_column("credentials", "aggregation_id").await?;
    let mut aggregation_sources = Vec::new();
    let mut aggregation_joins = Vec::new();
    if has_issuers {
        aggregation_sources.push("i.aggregation_id");
        aggregation_joins.push("LEFT JOIN issuers i ON i.issuer = c.issuer");
    }
    if has_issuer_aggregations {
        aggregation_sources.push("ia.aggregation_id");
        aggregation_joins.push("LEFT JOIN issuer_aggregations ia ON ia.issuer = c.issuer");
    }
    if has_credential_aggregation_id {
        aggregation_sources.push("c.aggregation_id");
    }
    let aggregation_id = if aggregation_sources.is_empty() {
        "NULL".to_owned()
    } else {
        format!("COALESCE({}, NULL)", aggregation_sources.join(", "))
    };
    let rows = db.query_all_raw(Statement::from_string(
        db.get_database_backend(),
        format!("SELECT c.issuer, c.public_key, {aggregation_id} AS aggregation_id FROM credentials c {} ORDER BY c.issuer", aggregation_joins.join(" ")),
    )).await?;
    let mut credentials = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("", "issuer")?;
        let key: serde_json::Value = row.try_get("", "public_key")?;
        let aggregation_id: Option<String> = row.try_get("", "aggregation_id")?;
        let aggregation_id = aggregation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        credentials.push(LegacyIssuerCredential {
            issuer: id,
            aggregation_id,
            public_key: key,
        });
    }
    Ok(credentials)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, EntityTrait, Statement};
    use sea_orm_migration::MigratorTrait;

    use super::*;
    use crate::outbound::sql::{
        Migrator,
        models::{Credentials, credentials},
    };

    #[tokio::test]
    async fn exports_from_pre_ownership_issuer_aggregations_schema() {
        let ownership_migration = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == "m20261022_000001_issuer_ownership")
            .expect("ownership migration must be registered");
        let db = crate::test_utils::sqlite_test_db(Some(ownership_migration as u32)).await;
        let aggregation_id = "00000000-0000-4000-8000-000000000001";
        let public_key = serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        let credential: credentials::ActiveModel =
            Credentials::new("pre-upgrade-issuer".to_owned(), public_key)
                .with_aggregation_id(aggregation_id.to_owned())
                .into();
        credentials::Entity::insert(credential)
            .exec(db.as_ref())
            .await
            .unwrap();
        db.execute_unprepared(&format!(
            "INSERT INTO issuer_aggregations (issuer, aggregation_id) VALUES ('pre-upgrade-issuer', '{aggregation_id}')"
        ))
        .await
        .unwrap();

        let exported = legacy_issuer_credentials(db.as_ref()).await.unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].issuer, "pre-upgrade-issuer");
        assert_eq!(exported[0].aggregation_id, aggregation_id);
    }

    #[tokio::test]
    async fn exports_v1_2_credentials_without_aggregation_id_columns() {
        let db = crate::test_utils::sqlite_test_db(Some(4)).await;
        let public_key: serde_json::Value =
            serde_json::from_str(crate::test_fixtures::TEST_EC_PUBLIC_JWK).unwrap();
        db.execute_raw(Statement::from_sql_and_values(
            db.get_database_backend(),
            "INSERT INTO credentials (issuer, public_key) VALUES (?, ?)",
            vec![
                "v1.2-issuer".into(),
                serde_json::to_string(&public_key).unwrap().into(),
            ],
        ))
        .await
        .unwrap();

        let exported = legacy_issuer_credentials(db.as_ref()).await.unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].issuer, "v1.2-issuer");
        assert!(uuid::Uuid::parse_str(&exported[0].aggregation_id).is_ok());
    }
}
