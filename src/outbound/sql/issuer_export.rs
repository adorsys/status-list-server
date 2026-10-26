use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};

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
    let rows = db.query_all_raw(Statement::from_string(
        db.get_database_backend(),
        "SELECT c.issuer, c.public_key, COALESCE(i.aggregation_id, c.aggregation_id) AS aggregation_id FROM credentials c LEFT JOIN issuers i ON i.issuer = c.issuer ORDER BY c.issuer".to_owned(),
    )).await?;
    let mut credentials = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("", "issuer")?;
        let key: serde_json::Value = row.try_get("", "public_key")?;
        let aggregation_id: Option<String> = row.try_get("", "aggregation_id")?;
        let aggregation_id = aggregation_id.ok_or_else(|| {
            std::io::Error::other(format!(
                "issuer {id} has no aggregation_id; resolve it before export"
            ))
        })?;
        credentials.push(LegacyIssuerCredential {
            issuer: id,
            aggregation_id,
            public_key: key,
        });
    }
    Ok(credentials)
}
