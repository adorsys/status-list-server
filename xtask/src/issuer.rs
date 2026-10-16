use std::{fs, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use color_eyre::eyre::{Context, Result, bail, ensure};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement, Value};
use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};

pub(crate) fn export(database_url: &str, output: &Path) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(export_async(database_url, output))
}

async fn export_async(database_url: &str, output: &Path) -> Result<()> {
    let db = Database::connect(database_url)
        .await
        .wrap_err("connect to the issuer database")?;
    let backend = db.get_database_backend();
    let query = match backend {
        DbBackend::MySql => {
            "SELECT issuer, CAST(public_key AS CHAR) AS public_key_json, aggregation_id FROM credentials ORDER BY issuer"
        }
        _ => {
            "SELECT issuer, CAST(public_key AS TEXT) AS public_key_json, aggregation_id FROM credentials ORDER BY issuer"
        }
    };
    let rows = db
        .query_all_raw(Statement::from_string(backend, query))
        .await
        .wrap_err("read issuer credentials")?;

    let mut document = String::from(
        "# Review this draft before deploying it. It contains public keys only.\nversion: 1\n",
    );
    let mut issuer_count = 0;
    for row in rows {
        if issuer_count == 0 {
            document.push_str("issuers:\n");
        }
        let issuer: String = row.try_get("", "issuer").wrap_err("read issuer id")?;
        let jwk_json: String = row
            .try_get("", "public_key_json")
            .wrap_err_with(|| format!("read public JWK for issuer {issuer:?}"))?;
        let mut public_key: JsonValue = serde_json::from_str(&jwk_json)
            .wrap_err_with(|| format!("parse public JWK for issuer {issuer:?}"))?;
        let aggregation_id: Option<String> = row
            .try_get("", "aggregation_id")
            .wrap_err_with(|| format!("read aggregation id for issuer {issuer:?}"))?;
        let aggregation_id = match aggregation_id {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                let update = match backend {
                    DbBackend::Postgres => {
                        "UPDATE credentials SET aggregation_id = $1 WHERE issuer = $2 AND aggregation_id IS NULL"
                    }
                    _ => {
                        "UPDATE credentials SET aggregation_id = ? WHERE issuer = ? AND aggregation_id IS NULL"
                    }
                };
                db.execute_raw(Statement::from_sql_and_values(
                    backend,
                    update,
                    [
                        Value::String(Some(id.clone())),
                        Value::String(Some(issuer.clone())),
                    ],
                ))
                .await
                .wrap_err_with(|| format!("assign aggregation id to issuer {issuer:?}"))?;
                id
            }
        };
        ensure!(
            uuid::Uuid::parse_str(&aggregation_id).is_ok(),
            "issuer {issuer:?} has an invalid aggregation_id {aggregation_id:?}"
        );
        let jwk = public_key.as_object_mut().ok_or_else(|| {
            color_eyre::eyre::eyre!("issuer {issuer:?} public key is not an object")
        })?;
        let alg = jwk
            .remove("alg")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| color_eyre::eyre::eyre!("issuer {issuer:?} public JWK has no alg"))?;
        jwk.remove("kid");
        jwk.remove("key_ops");
        let thumbprint = jwk_thumbprint(jwk)
            .wrap_err_with(|| format!("compute RFC 7638 thumbprint for issuer {issuer:?}"))?;
        let mut public_jwk = Map::new();
        for name in ["kty", "crv", "x", "y", "n", "e", "use"] {
            if let Some(value) = jwk.get(name) {
                public_jwk.insert(name.to_owned(), value.clone());
            }
        }
        ensure!(
            public_jwk.contains_key("kty"),
            "issuer {issuer:?} has no JWK kty"
        );
        ensure!(
            matches!(alg.as_str(), "ES256" | "ES384" | "EdDSA" | "PS256"),
            "issuer {issuer:?} has unsupported alg {alg:?}"
        );
        document.push_str(&format!(
            "  - id: {}\n    aggregation_id: {}\n    tier: standard\n    keys:\n      - kid: {}\n        alg: {}\n        jwk: {}\n",
            yaml_quote(&issuer),
            yaml_quote(&aggregation_id),
            yaml_quote(&thumbprint),
            yaml_quote(&alg),
            serde_json::to_string(&public_jwk)?
        ));
        issuer_count += 1;
    }
    if issuer_count == 0 {
        document.push_str("issuers: []\n");
    }
    document.push_str("admins: []\n");
    fs::write(output, document)
        .wrap_err_with(|| format!("write registry draft to {}", output.display()))?;
    db.close().await.wrap_err("close issuer database")?;
    println!("Exported issuer registry draft to {}", output.display());
    Ok(())
}

fn yaml_quote(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn jwk_thumbprint(jwk: &Map<String, JsonValue>) -> Result<String> {
    let kty = jwk
        .get("kty")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let members: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        "RSA" => &["e", "kty", "n"],
        _ => bail!("unsupported JWK key type {kty:?}"),
    };
    let mut canonical = Map::new();
    for name in members {
        let value = jwk
            .get(*name)
            .ok_or_else(|| color_eyre::eyre::eyre!("JWK is missing thumbprint member {name}"))?;
        canonical.insert((*name).to_owned(), value.clone());
    }
    let digest = Sha256::digest(serde_json::to_vec(&canonical)?);
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7638_thumbprint_ignores_non_thumbprint_members() {
        let jwk: Map<String, JsonValue> = serde_json::from_str(
            r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF4","y":"x_FEzRu9kV" ,"kid":"old","alg":"ES256"}"#,
        )
        .unwrap();
        let actual = jwk_thumbprint(&jwk).unwrap();
        let mut without_metadata = jwk;
        without_metadata.remove("kid");
        without_metadata.remove("alg");
        assert_eq!(actual, jwk_thumbprint(&without_metadata).unwrap());
        assert_eq!(actual.len(), 43);
    }
}
