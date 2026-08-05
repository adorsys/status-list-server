#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Insert error: {0}")]
    InsertError(String),
    #[error("Find error: {0}")]
    FindError(String),
    #[error("Update error: {0}")]
    UpdateError(String),
    #[error("Delete error: {0}")]
    DeleteError(String),
    #[error("Could not store entity")]
    CouldNotStoreEntity,
    #[error("Repository not set")]
    RepositoryNotSet,
    #[error("Duplicate entry")]
    DuplicateEntry,
}

// There is deliberately no `impl From<sea_orm::DbErr>` for this type, nor for
// `StatusListError` / `CredentialError`.
//
// A blanket conversion would make `?` on a `DbErr` compile anywhere, and every
// such conversion silently discards `DbErr::sql_err()` — turning a unique-key
// violation into a generic backend error, and a racing publish into a 500
// instead of a 409 (#143, #244). Requiring `.map_err(map_insert_err)` at each
// insert site keeps that classification an explicit, reviewable decision rather
// than something a one-character edit can drop.
//
// The `Generic` variant went with it: it existed only as that impl's output, and
// an unclassified catch-all is the same trapdoor wearing a different hat.
