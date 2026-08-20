//! Throwaway MySQL and Postgres databases with the migrations already applied,
//! for tests that need a real backend rather than `MockDatabase`.
//!
//! These live here rather than inside `store`'s `#[cfg(test)] mod test` because
//! the HTTP-layer publish tests need them too: an item inside a private test
//! module has no path nameable from another module, whatever its visibility.
//!
//! Each submodule carries only its backend's own feature gate. Both call
//! `Migrator::up`, but `Migrator` is re-exported unconditionally from
//! [`crate::outbound::sql`], whose own gate any consumer of these fixtures
//! already satisfies.
//!
//! # Isolation
//!
//! One container per *process*, held in a `OnceCell`, and one freshly created
//! database per *call*. Tests therefore never share tables, and the per-call
//! cost after the first is a `CREATE DATABASE` plus a migration run rather than
//! a container boot.
//!
//! Pools are pinned with `max_connections(1).min_connections(1)` so a test that
//! wants two genuinely distinct connections gets them: with a shared multi-slot
//! pool, both halves of a contention test can be handed the same connection and
//! the row lock they mean to fight over is never contended. Tests needing an
//! extra pool of known size call [`mysql_helpers::connect_to_test_db`].
//!
//! # Concurrency
//!
//! The `OnceCell` bounds containers per process, not per run: under
//! `cargo nextest` every test executes in its own process, so the cell is
//! initialised once per test and parallel tests still boot a container apiece.
//! That is what the `containers` test group in `.config/nextest.toml` is for —
//! it serialises these alongside the ACME suite in `tests/cert_provisioning.rs`,
//! which starts four containers of its own. Booting several servers at once
//! starves them of CPU during init and they fail before any test code runs:
//! MySQL reports `WaitContainer(StartupTimeout)`, pebble simply times out.
//!
//! The group selects database tests by `mysql`/`postgres` in the test name, so
//! keep that substring in the name of any new one, and confirm with
//! `cargo nextest show-config test-groups`. Under plain `cargo test` the
//! equivalent is `--test-threads=1` — though there the `OnceCell` does share a
//! single container across the whole binary, since it is one process.

/// MySQL fixture. The container is shared per process; each call carves its own
/// uniquely named database, so `Migrator::up` has nothing to race against.
#[cfg(feature = "mysql")]
pub(crate) mod mysql_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::{
        mysql::Mysql as MysqlImage,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };
    use tokio::sync::OnceCell;

    static MYSQL_CONTAINER: OnceCell<ContainerAsync<MysqlImage>> = OnceCell::const_new();

    /// A migrated, test-private database on the shared container. The container
    /// itself is `&'static`, so unlike a per-test container this can be dropped
    /// without cutting off connections handed out earlier.
    pub(crate) struct MysqlTestDb {
        #[allow(dead_code)]
        pub(crate) _container: &'static ContainerAsync<MysqlImage>,
        /// Connection URL for this test's database, for opening further pools —
        /// see [`connect_to_test_db`].
        pub(crate) url: String,
    }

    impl MysqlTestDb {
        pub(crate) async fn start() -> Self {
            let node = MYSQL_CONTAINER
                .get_or_init(|| async {
                    MysqlImage::default()
                        .with_tag("26.7")
                        .start()
                        .await
                        .expect("Failed to start MySQL container")
                })
                .await;

            let host = node.get_host().await.expect("Failed to resolve MySQL host");
            let port = node
                .get_host_port_ipv4(3306)
                .await
                .expect("Failed to resolve MySQL port");

            // Connect without a database first, to create this test's own.
            let admin_url = format!("mysql://{host}:{port}");
            let db_name = format!("test_{}", uuid::Uuid::new_v4().simple());

            let mut admin_opt = sea_orm::ConnectOptions::new(admin_url);
            admin_opt.max_connections(1).min_connections(1);
            let admin_conn = sea_orm::Database::connect(admin_opt)
                .await
                .expect("Failed to connect to MySQL admin");
            admin_conn
                .execute_unprepared(&format!(
                    "CREATE DATABASE {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                ))
                .await
                .expect("Failed to create test database");

            let url = format!("mysql://{host}:{port}/{db_name}");
            let db = Self::connect_pinned(&url).await;
            crate::outbound::sql::Migrator::up(db.as_ref(), None)
                .await
                .expect("Failed to run migrations on MySQL");

            Self {
                _container: node,
                url,
            }
        }

        /// Opens a fresh single-connection pool against this test's database.
        pub(crate) async fn connection(&self) -> Arc<DatabaseConnection> {
            Self::connect_pinned(&self.url).await
        }

        async fn connect_pinned(url: &str) -> Arc<DatabaseConnection> {
            let mut opt = sea_orm::ConnectOptions::new(url.to_owned());
            opt.max_connections(1).min_connections(1);
            Arc::new(
                sea_orm::Database::connect(opt)
                    .await
                    .expect("Failed to connect to MySQL"),
            )
        }
    }

    /// Opens an additional pool of a caller-chosen size against an
    /// already-migrated database. Contention tests use this to hold a known
    /// number of connections; ordinary tests want [`MysqlTestDb::connection`].
    pub(crate) async fn connect_to_test_db(
        mysql_url: &str,
        max_connections: u32,
    ) -> DatabaseConnection {
        let mut opt = sea_orm::ConnectOptions::new(mysql_url.to_string());
        opt.max_connections(max_connections)
            .min_connections(max_connections);
        sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to MySQL test database")
    }

    /// Backward-compatible helper that creates a new test database.
    /// Prefer [`MysqlTestDb::start`] for new tests.
    pub(crate) async fn mysql_connection() -> MysqlTestDb {
        MysqlTestDb::start().await
    }
}

/// Postgres fixture. As with MySQL the container is shared per process and each
/// call carves its own database; this one hands back the connection directly,
/// since no Postgres test needs a second pool.
#[cfg(feature = "postgres-tests")]
pub(crate) mod postgres_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::{
        postgres::Postgres as PostgresImage,
        testcontainers::{ContainerAsync, runners::AsyncRunner},
    };
    use tokio::sync::OnceCell;

    static POSTGRES_CONTAINER: OnceCell<ContainerAsync<PostgresImage>> = OnceCell::const_new();

    pub(crate) struct PostgresTestDb {
        #[allow(dead_code)]
        pub(crate) _container: &'static ContainerAsync<PostgresImage>,
        pub(crate) db: Arc<DatabaseConnection>,
        /// Connection URL for this test's database, for opening further pools —
        /// see [`connect_to_test_db`].
        pub(crate) url: String,
    }

    /// Opens an additional pool of a caller-chosen size against an
    /// already-migrated database. The counterpart of
    /// [`super::mysql_helpers::connect_to_test_db`]; contention tests need it
    /// because two halves sharing one multi-slot pool can be handed the same
    /// connection, and the row lock they mean to fight over is never contended.
    pub(crate) async fn connect_to_test_db(
        postgres_url: &str,
        max_connections: u32,
    ) -> DatabaseConnection {
        let mut opt = sea_orm::ConnectOptions::new(postgres_url.to_string());
        opt.max_connections(max_connections)
            .min_connections(max_connections);
        sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to Postgres test database")
    }

    pub(crate) async fn postgres_connection() -> PostgresTestDb {
        let node = POSTGRES_CONTAINER
            .get_or_init(|| async {
                PostgresImage::default()
                    .start()
                    .await
                    .expect("Failed to start Postgres container")
            })
            .await;
        let host = node
            .get_host()
            .await
            .expect("Failed to resolve Postgres host");
        let port = node
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to resolve Postgres port");

        // testcontainers' Postgres image defaults to postgres/postgres/postgres.
        let admin_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let db_name = format!("test_{}", uuid::Uuid::new_v4().simple());

        let mut admin_opt = sea_orm::ConnectOptions::new(admin_url);
        admin_opt.max_connections(1).min_connections(1);
        let admin_conn = sea_orm::Database::connect(admin_opt)
            .await
            .expect("Failed to connect to Postgres admin");
        admin_conn
            .execute_unprepared(&format!("CREATE DATABASE {db_name}"))
            .await
            .expect("Failed to create Postgres test database");

        let url = format!("postgres://postgres:postgres@{host}:{port}/{db_name}");
        let mut opt = sea_orm::ConnectOptions::new(url.clone());
        opt.max_connections(1).min_connections(1);
        let db = sea_orm::Database::connect(opt)
            .await
            .expect("Failed to connect to Postgres");
        crate::outbound::sql::Migrator::up(&db, None)
            .await
            .expect("Failed to run migrations on Postgres");

        PostgresTestDb {
            _container: node,
            db: Arc::new(db),
            url,
        }
    }
}
