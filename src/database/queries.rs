use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow};
use std::result::Result::Ok;

use crate::model::{Credentials, StatusListToken};

use super::{
    error::RepositoryError,
    repository::{Repository, Store, Table},
};

impl<T> Repository<T> for Store<T>
where
    T: Sized + Clone + Send + Sync + 'static,
    T: Unpin,
    T: for<'a> FromRow<'a, PgRow>,
    T: Serialize + for<'de> Deserialize<'de>,
{
    fn get_table(&self) -> Table<T> {
        self.table.clone()
    }
}

pub struct MockStore<T> {
    pub(crate) repository: Arc<RwLock<HashMap<String, T>>>,
}

#[async_trait]
impl Repository<StatusListToken> for MockStore<StatusListToken> {
    fn get_table(&self) -> Table<StatusListToken> {
        unimplemented!("this is not real db")
    }
    async fn insert_one(&self, entity: StatusListToken) -> Result<(), RepositoryError> {
        self.repository
            .write()
            .unwrap()
            .insert(entity.list_id.clone(), entity);
        Ok(())
    }

    async fn find_one_by(&self, value: String) -> Result<Option<StatusListToken>, RepositoryError> {
        let a = self.repository.read().unwrap().get(&value).cloned();

        Ok(a)
    }

    async fn update_one(
        &self,
        issuer: String,
        entity: StatusListToken,
    ) -> Result<bool, RepositoryError> {
        let mut repo = self.repository.write().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut e) = repo.entry(issuer) {
            e.insert(entity);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        if self.repository.write().unwrap().remove(&value).is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl Repository<Credentials> for MockStore<Credentials> {
    fn get_table(&self) -> Table<Credentials> {
        unimplemented!("this is not real db")
    }
    async fn insert_one(&self, entity: Credentials) -> Result<(), RepositoryError> {
        self.repository
            .write()
            .unwrap()
            .insert(entity.issuer.clone(), entity);
        Ok(())
    }

    async fn find_one_by(&self, value: String) -> Result<Option<Credentials>, RepositoryError> {
        let a = self.repository.read().unwrap().get(&value).cloned();
        Ok(a)
    }

    async fn update_one(
        &self,
        issuer: String,
        entity: Credentials,
    ) -> Result<bool, RepositoryError> {
        if self.repository.read().unwrap().contains_key(&issuer) {
            self.repository.write().unwrap().insert(issuer, entity);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_by(&self, value: String) -> Result<bool, RepositoryError> {
        if self.repository.write().unwrap().remove(&value).is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;

    use serde_json::json;
    use sqlx::Executor;

    use crate::{
        database::{
            connection::establish_connection,
            repository::{Repository, Store, Table},
        },
        model::Credentials,
    };

    #[tokio::test]
    async fn test() {
        env::set_var(
            "DATABASE_URL",
            "postgres://myuser:mypassword@localhost:5432/mydatabase",
        );

        let conn = establish_connection().await;
        conn.execute(include_str!("./migrations/001_status_list.sql"))
            .await
            .expect("Failed to initialize DB");

        let entity = Credentials::new(
            "issuer1".to_string(),
            json!("public_key"),
            "alg".to_string(),
        );
        let new_entity = Credentials::new(
            "issuer2".to_string(),
            json!("public_key"),
            "alg".to_string(),
        );

        let store: Store<Credentials> = Store {
            table: Table::new(conn, "credentials".to_string(), "issuer".to_string()),
        };

        // test inserting
        store.insert_one(entity.clone()).await.unwrap();

        // test finding
        let credential = store.find_one_by("issuer1".to_string()).await.unwrap();
        let credential = credential.unwrap();
        let issuer = credential.issuer.replace("\"", "");

        let alg = credential.alg.replace("\"", "");
        let public_key = serde_json::to_value(&credential.public_key).unwrap();
        let normalised_credential = Credentials::new(issuer.to_string(), public_key, alg);
        assert_eq!(normalised_credential, entity);

        // test update functionality
        let a = store
            .update_one("issuer1".to_string(), new_entity)
            .await
            .unwrap();
        assert!(a);

        // test delete functionality
        let a = store.delete_by("issuer2".to_string()).await.unwrap();
        assert!(a);
    }
}
