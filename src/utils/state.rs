use std::sync::Arc;

use crate::{
    database::{
        connection::establish_connection,
        repository::{Repository, Store, Table},
    },
    model::{Credentials, StatusListToken},
};
#[derive(Clone)]
pub struct AppState {
    pub repository: Option<AppStateRepository>,
}

#[derive(Clone)]
pub struct AppStateRepository {
    pub credential_repository: Arc<dyn Repository<Credentials>>,
    pub status_list_token_repository: Arc<dyn Repository<StatusListToken>>,
}

impl AppStateRepository {
    pub fn from(
        credential_repository: Arc<Store<Credentials>>,
        status_list_token_repository: Arc<Store<StatusListToken>>,
    ) -> Self {
        Self {
            credential_repository,
            status_list_token_repository,
        }
    }
}

pub async fn setup() -> AppState {
    let conn = establish_connection().await;
    let credential_repo: Store<Credentials> = Store {
        table: Table::new(conn.clone(), "credentials".to_owned(), "issuer".to_owned()),
    };
    let status_list_repo: Store<StatusListToken> = Store {
        table: Table::new(conn, "status_list_tokens".to_owned(), "list_id".to_owned()),
    };

    AppState {
        repository: Some(AppStateRepository {
            credential_repository: Arc::new(credential_repo),
            status_list_token_repository: Arc::new(status_list_repo),
        }),
    }
}
