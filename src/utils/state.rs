use crate::{
    database::repository::Store,
    model::{Credentials, StatusListToken},
};

pub struct AppState {
    pub repository: Option<AppStateRepository>,
}

pub struct AppStateRepository {
    pub credential_repository: Store<Credentials>,
    pub status_list_token_repository: Store<StatusListToken>,
}
