use diesel::{
    query_dsl::methods::{FilterDsl, SelectDsl},
    ExpressionMethods, SelectableHelper,
};
use diesel_async::RunQueryDsl;

use crate::model::Credentials;

use super::{
    connection::Database,
    errors::RepositoryError,
    schema::credentials::{dsl::credentials, issuer},
};

/// get credentials using issuer as `id`
pub async fn get_credential_and_alg(
    id: String,
    conn: &Database,
) -> Result<Credentials, RepositoryError> {
    let mut conn = conn.get().await.map_err(|_| RepositoryError::PoolError)?;
    let cred = credentials
        .filter(issuer.eq(id))
        .select(Credentials::as_select())
        .first(&mut conn)
        .await
        .map_err(|_| RepositoryError::FetchError)?;
    Ok(cred)
}
