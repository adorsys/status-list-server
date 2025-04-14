use std::{collections::HashMap, sync::Arc};

use std::sync::RwLock;

use crate::utils::keygen::Keypair;
use crate::{
    database::queries::MockStore,
    model::{Credentials, StatusListToken},
    utils::state::{AppState, AppStateRepository},
};

pub fn test_setup(
    credential_repo: Arc<RwLock<HashMap<String, Credentials>>>,
    status_list_repo: Arc<RwLock<HashMap<String, StatusListToken>>>,
    server_keypair: Option<Keypair>,
) -> AppState {
    let repository = AppStateRepository {
        credential_repository: Arc::new(MockStore {
            repository: credential_repo,
        }),
        status_list_token_repository: Arc::new(MockStore {
            repository: status_list_repo,
        }),
    };
    AppState {
        repository: Some(repository),
        server_keypair,
    }
}
