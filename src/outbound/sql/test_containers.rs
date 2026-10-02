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
//! Each fixture owns its container and a freshly migrated database. Keep the
//! fixture in scope until all pools and spawned tasks using that database have
//! finished. Dropping the fixture removes its container, including during panic
//! unwinding. Static container handles must not be used: statics are never dropped
//! at process exit, so nextest would leave a database server behind for every test.
//!
//! Cleanup requires a live Tokio runtime and a reachable Docker daemon. SIGTERM
//! (including nextest slow-timeouts), Ctrl-C, SIGKILL, process aborts, or
//! `TESTCONTAINERS_COMMAND=keep` can leave containers behind without running Drop.
//! To identify every SQL fixture from one run, set a unique run ID before testing:
//!
//! ```sh
//! export STATUS_LIST_TEST_RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
//! cargo nextest run --workspace --all-targets --all-features
//! ```
//!
//! After that run has stopped, inspect and remove only its SQL containers:
//!
//! ```sh
//! : "${STATUS_LIST_TEST_RUN_ID:?Set the interrupted run ID first}"
//! docker container ls -a --filter label=org.adorsys.status-list-server.fixture=sql \
//!   --filter "label=org.adorsys.status-list-server.run=$STATUS_LIST_TEST_RUN_ID"
//! for id in $(docker container ls -aq --filter label=org.adorsys.status-list-server.fixture=sql \
//!   --filter "label=org.adorsys.status-list-server.run=$STATUS_LIST_TEST_RUN_ID"); do
//!   docker container rm -f "$id"
//! done
//! ```
//!
//! Without an explicit run ID, each process generates and prints a UUID; its
//! containers still carry both labels. These filters never select Redis fixtures
//! or containers from other projects. The cleanup regression tests additionally
//! require the Docker CLI on PATH; ordinary fixtures use the Docker API directly.
//!
//! Pools are pinned with `max_connections(1).min_connections(1)` so a test that
//! wants two genuinely distinct connections gets them: with a shared multi-slot
//! pool, both halves of a contention test can be handed the same connection and
//! the row lock they mean to fight over is never contended. Tests needing an
//! extra pool of known size call [`mysql_helpers::connect_to_test_db`].
//!
//! # Concurrency
//!
//! The `containers` test group in `.config/nextest.toml` bounds simultaneous
//! database and ACME container starts under nextest. Scoped ownership also bounds
//! resource use over repeated runs: completed tests no longer retain servers.
//! Keep `mysql` or `postgres` in new database test names so they join that group.
//! A shared process-wide semaphore limits MySQL and Postgres fixtures to four
//! live containers under ordinary `cargo test`, regardless of test thread count.
//! The permit is held until container cleanup completes. This is a per-process
//! limit; nextest's group is still needed to bound its separate test processes.

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
        // Declaration order keeps the slot reserved through cleanup, including
        // when database creation or migration panics before the fixture is built.
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

/// MySQL fixture owning a container and a uniquely named migrated database.
#[cfg(feature = "mysql")]
pub(crate) mod mysql_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::{mysql::Mysql as MysqlImage, testcontainers::ImageExt};

    /// Keep this guard alive until all connections and tasks using its URL finish.
    /// Drop it inside a live Tokio runtime; pools do not retain the container.
    #[must_use = "keep the fixture alive until all database operations finish"]
    pub(crate) struct MysqlTestDb {
        /// Connection URL for this test's database, for opening further pools —
        /// see [`connect_to_test_db`].
        pub(crate) url: String,
        container: super::lifecycle::FixtureContainer<MysqlImage>,
    }

    impl MysqlTestDb {
        pub(crate) async fn start() -> Self {
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
                container: node,
                url,
            }
        }

        pub(super) fn container_id(&self) -> &str {
            self.container.inner.id()
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

/// Postgres fixture owning a container, migrated database, and connection pool.
#[cfg(feature = "postgres-tests")]
pub(crate) mod postgres_helpers {
    use sea_orm::{ConnectionTrait, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;
    use testcontainers_modules::postgres::Postgres as PostgresImage;

    /// Keep this guard alive until all pools and tasks finish, then drop it inside
    /// a live Tokio runtime. Cloned pools do not retain the container.
    #[must_use = "keep the fixture alive until all database operations finish"]
    pub(crate) struct PostgresTestDb {
        pub(crate) db: Arc<DatabaseConnection>,
        /// Connection URL for this test's database, for opening further pools —
        /// see [`connect_to_test_db`].
        pub(crate) url: String,
        // Release our pool reference first; callers may still hold clones.
        container: super::lifecycle::FixtureContainer<PostgresImage>,
    }

    impl PostgresTestDb {
        pub(super) fn container_id(&self) -> &str {
            self.container.inner.id()
        }
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
        crate::outbound::sql::Migrator::up(&db, None)
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

    // testcontainers 0.27 waits for removal inside Drop on both Tokio runtime
    // flavors. Revisit these immediate assertions when upgrading the crate.
    /// Listing must succeed: an unreachable daemon must not look like cleanup.
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
            if let Ok(run_id) = std::env::var("STATUS_LIST_TEST_RUN_ID")
                && !run_id.is_empty()
            {
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
        // The returned pool remains usable while its fixture is retained.
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
