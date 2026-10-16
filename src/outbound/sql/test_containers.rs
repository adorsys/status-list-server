//! Hold one fixture per test: waiting on a second can deadlock the four-container limit.
//! Pools are pinned to one connection so contention tests really get two.
//! Cleanup steps for containers left by a killed run: see CONTRIBUTING.md.

#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
mod lifecycle {
    use std::sync::OnceLock;
    use testcontainers_modules::testcontainers::{
        ContainerAsync, ContainerRequest, Image, ImageExt, runners::AsyncRunner,
    };
    use tokio::sync::{Semaphore, SemaphorePermit};

    static FIXTURE_SLOTS: Semaphore = Semaphore::const_new(4);
    static RUN_ID: OnceLock<String> = OnceLock::new();

    pub(super) struct FixtureContainer<I: Image> {
        pub(super) inner: ContainerAsync<I>,
        // Field order matters: the permit must drop after the container.
        _permit: SemaphorePermit<'static>,
    }

    pub(super) async fn start_with_retry<I: Image>(
        backend: &str,
        image: impl Fn() -> ContainerRequest<I>,
    ) -> FixtureContainer<I> {
        let permit = FIXTURE_SLOTS
            .acquire()
            .await
            .expect("fixture semaphore closed");
        let run_id = RUN_ID.get_or_init(|| {
            let id = std::env::var("STATUS_LIST_TEST_RUN_ID")
                .ok()
                .filter(|id| !id.is_empty())
                .or_else(|| {
                    std::env::var("NEXTEST_RUN_ID")
                        .ok()
                        .filter(|id| !id.is_empty())
                })
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            eprintln!("SQL fixture run ID: {id}");
            id
        });
        let mut last_err = None;
        for attempt in 1..=3 {
            match image()
                .with_label("org.adorsys.status-list-server.fixture", "sql")
                .with_label("org.adorsys.status-list-server.run", run_id)
                .start()
                .await
            {
                Ok(container) => {
                    return FixtureContainer {
                        inner: container,
                        _permit: permit,
                    };
                }
                Err(err) => {
                    last_err = Some(err);
                    if attempt < 3 {
                        tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
                    }
                }
            }
        }
        panic!("Failed to start {backend} container after 3 attempts: {last_err:?}");
    }
}

#[cfg(feature = "mysql")]
pub(crate) mod mysql_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::{mysql::Mysql as MysqlImage, testcontainers::ImageExt};

    /// Drop inside a Tokio runtime; pools don't keep the container alive.
    #[must_use = "keep the fixture alive until all database operations finish"]
    pub(crate) struct MysqlTestDb {
        pub(crate) url: String,
        container: super::lifecycle::FixtureContainer<MysqlImage>,
    }

    impl MysqlTestDb {
        pub(crate) async fn start() -> Self {
            Self::start_migrated(None).await
        }

        /// Applies only the first `steps` migrations (`None` applies all).
        pub(crate) async fn start_migrated(steps: Option<u32>) -> Self {
            let node = super::lifecycle::start_with_retry("MySQL", || {
                MysqlImage::default().with_tag("26.7")
            })
            .await;

            let host = node
                .inner
                .get_host()
                .await
                .expect("Failed to resolve MySQL host");
            let port = node
                .inner
                .get_host_port_ipv4(3306)
                .await
                .expect("Failed to resolve MySQL port");

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
            crate::outbound::sql::Migrator::up(db.as_ref(), steps)
                .await
                .expect("Failed to run migrations on MySQL");

            Self {
                container: node,
                url,
            }
        }

        pub(super) fn container_id(&self) -> &str {
            self.container.inner.id()
        }

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

    pub(crate) async fn mysql_connection() -> MysqlTestDb {
        MysqlTestDb::start().await
    }
}

#[cfg(feature = "postgres-tests")]
pub(crate) mod postgres_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::postgres::Postgres as PostgresImage;

    /// Drop inside a Tokio runtime; cloned pools don't keep the container alive.
    #[must_use = "keep the fixture alive until all database operations finish"]
    pub(crate) struct PostgresTestDb {
        pub(crate) db: Arc<DatabaseConnection>,
        pub(crate) url: String,
        // Release our pool reference first; callers may still hold clones.
        container: super::lifecycle::FixtureContainer<PostgresImage>,
    }

    impl PostgresTestDb {
        pub(super) fn container_id(&self) -> &str {
            self.container.inner.id()
        }
    }

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
        postgres_connection_migrated(None).await
    }

    /// Applies only the first `steps` migrations (`None` applies all).
    pub(crate) async fn postgres_connection_migrated(steps: Option<u32>) -> PostgresTestDb {
        let node =
            super::lifecycle::start_with_retry("Postgres", || PostgresImage::default().into())
                .await;
        let host = node
            .inner
            .get_host()
            .await
            .expect("Failed to resolve Postgres host");
        let port = node
            .inner
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
        crate::outbound::sql::Migrator::up(&db, steps)
            .await
            .expect("Failed to run migrations on Postgres");

        PostgresTestDb {
            container: node,
            db: Arc::new(db),
            url,
        }
    }
}

#[cfg(all(test, any(feature = "mysql", feature = "postgres-tests")))]
mod cleanup_tests {
    use sea_orm::ConnectionTrait;

    // Relies on testcontainers 0.27 removing containers inside Drop.
    async fn assert_container_exists(id: &str, expected: bool) {
        let output = tokio::process::Command::new("docker")
            .args([
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--format",
                "{{.ID}}|{{.Label \"org.adorsys.status-list-server.fixture\"}}|{{.Label \"org.adorsys.status-list-server.run\"}}",
                "--filter",
                &format!("id={id}"),
            ])
            .output()
            .await
            .expect("Docker CLI is required to verify fixture cleanup");
        assert!(
            output.status.success(),
            "Docker container lookup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let found = String::from_utf8(output.stdout).unwrap();
        let container = found
            .lines()
            .find(|line| line.split('|').next() == Some(id));
        assert_eq!(container.is_some(), expected, "container {id}");
        if let Some(container) = container {
            let labels: Vec<_> = container.splitn(3, '|').collect();
            assert_eq!(labels[1], "sql", "project label missing on {id}");
            assert!(!labels[2].is_empty(), "run label missing on {id}");
            let expected_run_id = ["STATUS_LIST_TEST_RUN_ID", "NEXTEST_RUN_ID"]
                .into_iter()
                .filter_map(|key| std::env::var(key).ok())
                .find(|id| !id.is_empty());
            if let Some(run_id) = expected_run_id {
                assert_eq!(labels[2], run_id, "wrong run label on {id}");
            }
        }
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn mysql_fixture_removes_container_after_scope() {
        let fixture = super::mysql_helpers::MysqlTestDb::start().await;
        let id = fixture.container_id().to_owned();
        assert_container_exists(&id, true).await;
        fixture
            .connection()
            .await
            .execute_unprepared("SELECT 1")
            .await
            .unwrap();
        drop(fixture);
        assert_container_exists(&id, false).await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn postgres_fixture_removes_container_after_scope() {
        let fixture = super::postgres_helpers::postgres_connection().await;
        let id = fixture.container_id().to_owned();
        assert_container_exists(&id, true).await;
        fixture.db.execute_unprepared("SELECT 1").await.unwrap();
        drop(fixture);
        assert_container_exists(&id, false).await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn mysql_fixture_removes_container_on_panic() {
        let fixture = super::mysql_helpers::MysqlTestDb::start().await;
        let id = fixture.container_id().to_owned();
        assert_container_exists(&id, true).await;
        let failure = tokio::spawn(async move {
            let _fixture = fixture;
            panic!("simulate a failed database test");
        })
        .await
        .expect_err("the task must panic");
        assert!(failure.is_panic());
        assert_container_exists(&id, false).await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn postgres_fixture_removes_container_on_panic() {
        let fixture = super::postgres_helpers::postgres_connection().await;
        let id = fixture.container_id().to_owned();
        assert_container_exists(&id, true).await;
        let failure = tokio::spawn(async move {
            let _fixture = fixture;
            panic!("simulate a failed database test");
        })
        .await
        .expect_err("the task must panic");
        assert!(failure.is_panic());
        assert_container_exists(&id, false).await;
    }
}
