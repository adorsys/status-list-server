use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow};

use super::repository::{Repository, Store, Table};

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
            "postgres://myuser:dastro12345@localhost:5433/status_list_db",
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
