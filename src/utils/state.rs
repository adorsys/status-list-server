use crate::{
    database::{
        connection::establish_connection,
        repository::{Store, Table},
    },
    model::{Credentials, StatusListToken},
};
#[derive(Clone)]
pub struct AppState {
    pub repository: Option<AppStateRepository>,
}

#[derive(Clone)]
pub struct AppStateRepository {
    pub credential_repository: Store<Credentials>,
    pub status_list_token_repository: Store<StatusListToken>,
}

impl AppStateRepository {
    pub fn from(
        credential_repository: Store<Credentials>,
        status_list_token_repository: Store<StatusListToken>,
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
        table: Table::new(conn.clone(), "credentials", "issuer".to_owned()),
    };
    let status_list_repo: Store<StatusListToken> = Store {
        table: Table::new(conn, "status_list_tokens", "status_list_id".to_owned()),
    };

    AppState {
        repository: Some(AppStateRepository {
            credential_repository: credential_repo,
            status_list_token_repository: status_list_repo,
        }),
    }
}
