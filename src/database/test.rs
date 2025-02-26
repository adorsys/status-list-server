/// get credentials using issuer as `id`
async fn get_credential_and_alg(
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

/// stores credentials with `issuer` as unique id. fails if issuer already exits
async fn store_credentials(
    credential: Credentials,
    conn: &Database,
) -> Result<(), RepositoryError> {
    let mut conn = conn.get().await.map_err(|_| RepositoryError::PoolError)?;
    diesel::insert_into(schema::credentials::table)
        .values(credential)
        .execute(&mut *conn)
        .await
        .map_err(|_| RepositoryError::StoreError)?;
    Ok(())
}

/// updates credentials associated to an issuer.
async fn update_credentials(
    id: String,
    credential: Credentials,
    conn: &Database,
) -> Result<(), RepositoryError> {
    let mut conn = conn.get().await.map_err(|_| RepositoryError::PoolError)?;
    let post = diesel::update(schema::credentials::dsl::credentials)
        .filter(issuer.eq(id))
        .set(credential);
    Ok(())
}