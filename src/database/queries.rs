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

    use sea_orm::MockDatabase;
    use serde_json::{json, to_string};

    use crate::{
        database::{
            connection::establish_connection,
            repository::{Repository, Store, Table},
        },
        model::Credentials,
    };

    pub struct MockStore {
        table: Table<Credentials>,
    }

    impl Repository<Credentials> for MockStore {
        fn get_table(&self) -> crate::database::repository::Table<Credentials> {
            unimplemented!("not real")
        }
    }
    #[tokio::test]
    async fn test() {
        let database = MockDatabase::new(sea_orm::DatabaseBackend::Postgres);
        let conn = database.into_connection();
        let mock = conn.as_mock_connection();

        env::set_var("DATABASE_URL", "postgres://postgres:mypassword@localhost:5432/statuslist?connect_timeout=30");
        let a = json!("dsaf");
        let entity = Credentials{issuer: "isuuer16".to_string(), public_key: a, alg: "[65]".to_string()};
        
        let conn = establish_connection().await;
        let mocktstore: Store<Credentials> = Store {
            table: Table::new(conn, "credentials", "issuer".to_string()),
        };
        
        // mocktstore.insert_one(entity.clone()).await.unwrap();
        let id = "isuuer16".to_string();
        let mut result = mocktstore.find_one_by(id).await.unwrap();
        result = Credentials {issuer: serde_json::to_string(&result.issuer).unwrap(), public_key: result.issuer.trim().into(), alg: result.alg.trim().to_string()};

        assert_eq!(result, entity)
    }
}
 