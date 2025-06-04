pub async fn serve_acme_challenge(
    Path(token): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.challenge_storage.get_challenge(&token).await {
        Ok(Some(challenge)) => {
            info!("Serving ACME challenge for token: {}", token);
            Ok((
                [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
                challenge,
            ))
        }
        Ok(None) => {
            warn!("Challenge not found for token: {}", token);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Error while retrieving challenge for token {token}: {e:?}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
