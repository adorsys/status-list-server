#[cfg(any(feature = "mysql", feature = "postgres-tests"))]
mod database_implementation {
    use std::sync::Arc;

    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{
        ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, Statement,
        TransactionTrait, Value,
    };

    use super::super::super::snapshot_txn_test_hook;
    use super::super::fixtures;
    use crate::outbound::sql::models::{
        Credentials, StatusList, StatusListHistoryRecord, StatusListRecord, status_list_history,
    };
    use crate::outbound::sql::{RepositoryError, SeaOrmStore};

    #[cfg(feature = "mysql")]
    use crate::outbound::sql::test_containers::mysql_helpers;
    #[cfg(feature = "postgres-tests")]
    use crate::outbound::sql::test_containers::postgres_helpers;

    /// A's guarded update + snapshot wins; B's concurrent guarded update blocks
    /// on A's row lock, loses the guard, and records no loser snapshot.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_concurrent_update_loses_guarded_update() {
        use std::time::{Duration, Instant};
        use tokio::sync::oneshot;

        let test_db = mysql_helpers::mysql_connection().await;

        let pool_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let pool_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let pool_verify = mysql_helpers::connect_to_test_db(&test_db.url, 2).await;
        let store_a = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_a));
        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_b));
        let store_verify = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_verify));

        // Seed a credential first (required for FK)
        let cred_key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
        let issuer = "issuer-contention-mysql";
        let cred_store = SeaOrmStore::<Credentials>::from_handle(store_a.db.clone());
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), cred_key))
            .await
            .unwrap();

        // Seed a status list at a known timestamp
        let base_timestamp = 1000i64;
        let list_id = "list-contention-mysql";
        let base_record = StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: "sub-contention".to_string(),
            updated_at: base_timestamp,
        };
        store_a.insert_one(base_record.clone()).await.unwrap();

        // Channels for coordination (using Instants for happens-before assertions)
        let (tx_a_ready, rx_a_ready) = oneshot::channel();
        let (tx_b_started, rx_b_started) = oneshot::channel();
        let (tx_a_release, rx_a_release) = oneshot::channel();
        let (tx_b_complete, rx_b_complete) = oneshot::channel::<(bool, Instant)>();

        snapshot_txn_test_hook::UPDATE_BEFORE_COMMIT
            .install(snapshot_txn_test_hook::Probe {
                list_id: list_id.to_string(),
                ready: tx_a_ready,
                release: rx_a_release,
            })
            .await;

        // Connection A: run the real update + snapshot method, pausing after
        // the snapshot insert and before commit while the row lock is held.
        let store_a_clone = store_a.clone();
        let base_record_a = base_record.clone();
        let handle_a = tokio::spawn(async move {
            let updated_at_a = base_timestamp + 1;
            let record_a = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-a".to_string(),
                },
                updated_at: updated_at_a,
                ..base_record_a.clone()
            };
            let snapshot_a = StatusListHistoryRecord {
                snapshot_id: "snap-contention-a".to_string(),
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: record_a.status_list.clone(),
                sub: record_a.sub.clone(),
                iat: updated_at_a,
                exp: updated_at_a + 900,
            };

            store_a_clone
                .update_one_with_snapshot(list_id, record_a, base_timestamp, snapshot_a)
                .await
                .expect("Update A should complete")
        });

        // Connection B: Try to update concurrently
        let store_b_clone = store_b.clone();
        let base_record_b = base_record.clone();
        let b_snapshot_id = "snap-contention-b".to_string();
        let b_snapshot_id_for_task = b_snapshot_id.clone();
        let handle_b = tokio::spawn(async move {
            // Wait for A to be ready (ensuring A holds the lock)
            rx_a_ready.await.expect("Failed to receive A ready");

            // Signal that B is starting
            tx_b_started.send(()).expect("Failed to signal B started");

            // Try to update - this should BLOCK until A commits
            // because InnoDB row locks are exclusive for writes
            let updated_at_b = base_timestamp + 2;
            let record_b = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-b".to_string(),
                },
                updated_at: updated_at_b,
                ..base_record_b.clone()
            };
            let snapshot_b = StatusListHistoryRecord {
                snapshot_id: b_snapshot_id_for_task,
                list_id: list_id.to_string(),
                issuer: issuer.to_string(),
                status_list: record_b.status_list.clone(),
                sub: record_b.sub.clone(),
                iat: updated_at_b,
                exp: updated_at_b + 900,
            };

            // This update uses the ORIGINAL base_timestamp as guard
            // After A commits, the row has updated_at = base_timestamp + 1
            // So this guard (base_timestamp) should miss → returns false
            let result = store_b_clone
                .update_one_with_snapshot(list_id, record_b, base_timestamp, snapshot_b)
                .await
                .expect("Update B should complete");

            // Capture completion immediately after the repository method returns.
            // No channel ordering is allowed to manufacture this timestamp.
            let b_done = Instant::now();

            tx_b_complete
                .send((result, b_done))
                .expect("Failed to send B result");
        });

        rx_b_started.await.expect("Failed to receive B started");

        // Give B a moment to reach MySQL and block on A's row lock.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B cannot complete before this instant if it is blocked on A's row
        // lock. Capturing before releasing A avoids a scheduler race after MySQL
        // has already released the lock but before this task resumes.
        let a_releasing_lock = Instant::now();
        tx_a_release.send(()).expect("Failed to release A");

        // Wait for both tasks with timeout, joining both handles for proper error reporting
        let timeout = Duration::from_secs(10);
        let (a_result, b_result) = tokio::join!(
            tokio::time::timeout(timeout, handle_a),
            tokio::time::timeout(timeout, handle_b)
        );

        // Unwrap results to get proper panic messages from either task
        let a_won = a_result
            .expect("Test timed out waiting for task A")
            .expect("Task A panicked");
        assert!(a_won, "Writer A should win the guarded update");
        b_result
            .expect("Test timed out waiting for task B")
            .expect("Task B panicked");

        // Receive the results from the oneshot channels
        let (b_won, b_done) = rx_b_complete.await.expect("Failed to receive B result");

        // Falsifiable ordering assertion: if B were not blocked on A's row lock,
        // it would complete during A's hold sleep, before A starts committing.
        assert!(
            b_done > a_releasing_lock,
            "B should complete only after A starts releasing the row lock (B: {:?}, A: {:?})",
            b_done,
            a_releasing_lock
        );

        // The CRITICAL assertion: B should NOT have won
        // B's guard was base_timestamp, but A changed updated_at to base_timestamp + 1
        // So B's WHERE updated_at = base_timestamp should affect 0 rows
        assert!(
            !b_won,
            "B should lose (0 rows affected) because A already advanced updated_at. \
         B blocked, then got a stale guard"
        );

        // Verify the final state has A's changes (use verify pool to avoid deadlock)
        let final_record = store_verify
            .find_one_by(list_id)
            .await
            .unwrap()
            .expect("Record should exist");
        assert_eq!(
            final_record.status_list.lst, "writer-a",
            "A's write should be persisted"
        );
        assert_eq!(
            final_record.updated_at,
            base_timestamp + 1,
            "updated_at should be A's timestamp"
        );

        // Verify A's winning snapshot was created.
        let history_store =
            SeaOrmStore::<StatusListHistoryRecord>::from_handle(store_verify.db.clone());
        let winning_snapshot = history_store
            .find_valid_at(list_id, base_timestamp + 1)
            .await
            .unwrap();
        assert_eq!(
            winning_snapshot
                .expect("A's winning snapshot should have been created")
                .snapshot_id,
            "snap-contention-a"
        );

        let verify_db = store_verify.db.current();
        let loser_snapshot = status_list_history::Entity::find_by_id(b_snapshot_id)
            .one(&*verify_db)
            .await
            .expect("Loser snapshot lookup should succeed");
        assert!(
            loser_snapshot.is_none(),
            "B's guard-miss path must not record a snapshot"
        );
    }

    /// The real publish race on two connections: writer B collides with writer
    /// A's still-uncommitted primary key, blocks until A commits, and must get
    /// `DuplicateEntry` (409), not a generic error (500), leaving no snapshot
    /// behind.
    #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
    async fn assert_concurrent_publish_loser_gets_conflict(
        pool_a: DatabaseConnection,
        pool_b: DatabaseConnection,
        pool_verify: DatabaseConnection,
        issuer: &'static str,
        list_id: &'static str,
        backend: &'static str,
    ) {
        use std::time::{Duration, Instant};
        use tokio::sync::oneshot;

        let store_a = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_a));
        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_b));
        let store_verify = SeaOrmStore::<StatusListRecord>::new(Arc::new(pool_verify));

        // status_lists.issuer is a foreign key onto credentials.issuer, so the
        // credential has to be committed before either writer starts.
        SeaOrmStore::<Credentials>::from_handle(store_verify.db.clone())
            .insert_one(Credentials::new(
                issuer.to_string(),
                serde_json::from_str(fixtures::TEST_EC_JWK).unwrap(),
            ))
            .await
            .unwrap();

        // `move` so both closures capture the `&'static str`s by copy and stay
        // `Copy` themselves — each spawned writer below needs its own.
        let record = move |lst: &str, updated_at: i64| StatusListRecord {
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: lst.to_string(),
            },
            sub: format!("sub-{list_id}"),
            updated_at,
        };
        let snapshot = move |snapshot_id: &str, iat: i64| StatusListHistoryRecord {
            snapshot_id: snapshot_id.to_string(),
            list_id: list_id.to_string(),
            issuer: issuer.to_string(),
            status_list: StatusList {
                bits: 1,
                lst: "initial".to_string(),
            },
            sub: format!("sub-{list_id}"),
            iat,
            exp: iat + 900,
        };

        let (tx_a_ready, rx_a_ready) = oneshot::channel();
        let (tx_b_started, rx_b_started) = oneshot::channel();
        let (tx_a_release, rx_a_release) = oneshot::channel();
        let (tx_b_done, rx_b_done) = oneshot::channel::<(Result<(), RepositoryError>, Instant)>();

        snapshot_txn_test_hook::INSERT_BEFORE_COMMIT
            .install(snapshot_txn_test_hook::Probe {
                list_id: list_id.to_string(),
                ready: tx_a_ready,
                release: rx_a_release,
            })
            .await;

        // Writer A: the winning publish, paused just before COMMIT while its
        // primary-key entry is still uncommitted.
        let handle_a = tokio::spawn(async move {
            store_a
                .insert_one_with_snapshot(record("writer-a", 1000), snapshot("snap-race-a", 1000))
                .await
        });

        // Writer B: the losing publish. Starts only once A is known to be
        // holding the uncommitted key.
        let handle_b = tokio::spawn(async move {
            rx_a_ready.await.expect("A never reached its pause point");
            tx_b_started.send(()).expect("failed to signal B started");

            let result = store_b
                .insert_one_with_snapshot(record("writer-b", 2000), snapshot("snap-race-b", 2000))
                .await;
            // Timestamped the instant the call returns, before any channel work,
            // so nothing downstream can manufacture the ordering.
            let b_done = Instant::now();
            tx_b_done
                .send((result, b_done))
                .expect("failed to send B result");
        });

        rx_b_started.await.expect("B never started");
        // Give B time to reach the database and block on A's key.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let a_releasing = Instant::now();
        tx_a_release.send(()).expect("failed to release A");

        let timeout = Duration::from_secs(30);
        let (a_join, b_join) = tokio::join!(
            tokio::time::timeout(timeout, handle_a),
            tokio::time::timeout(timeout, handle_b)
        );
        a_join
            .unwrap_or_else(|_| panic!("timed out waiting for writer A on {backend}"))
            .expect("writer A panicked")
            .unwrap_or_else(|e| panic!("writer A should win the publish on {backend}: {e:?}"));
        b_join
            .unwrap_or_else(|_| panic!("timed out waiting for writer B on {backend}"))
            .expect("writer B panicked");

        let (b_result, b_done) = rx_b_done.await.expect("failed to receive B result");

        // Falsifiable: if B had not blocked on A's uncommitted key it would have
        // finished during the sleep above, before A began committing.
        assert!(
            b_done > a_releasing,
            "B must block until A commits on {backend} — otherwise this is not a \
         race (B: {b_done:?}, A releasing: {a_releasing:?})"
        );

        // The property under test: a genuinely concurrent duplicate is still a
        // client conflict, not a server error.
        assert!(
            matches!(b_result, Err(RepositoryError::DuplicateEntry)),
            "the losing publisher of a real race must get DuplicateEntry (409) \
         on {backend}, not a generic error (500), got {b_result:?}"
        );

        // A's row won and B disturbed nothing.
        let row = store_verify
            .find_one_by(list_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("A's row must be committed on {backend}"));
        assert_eq!(
            row.status_list.lst, "writer-a",
            "A's publish must be the one that persisted on {backend}"
        );
        assert_eq!(
            row.updated_at, 1000,
            "B must not have overwritten A's row on {backend}"
        );

        let verify_db = store_verify.db.current();
        let loser_snapshot = status_list_history::Entity::find_by_id("snap-race-b")
            .one(&*verify_db)
            .await
            .expect("loser snapshot lookup should succeed");
        assert!(
            loser_snapshot.is_none(),
            "the losing publisher must not leave a snapshot behind on {backend}"
        );
    }

    /// The publish race on MySQL, whose driver reports duplicate keys as `1062`.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_mysql_concurrent_publish_loser_gets_conflict() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;
        assert_concurrent_publish_loser_gets_conflict(
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
            mysql_helpers::connect_to_test_db(&test_db.url, 2).await,
            "issuer-race-txn-mysql",
            "list-race-txn-mysql",
            "MySQL",
        )
        .await;
    }

    /// The same race on Postgres, the production backend and the one the issue
    /// singles out: a failed statement poisons the transaction (`25P02`), so a
    /// classification taken from anywhere but the original `23505` degrades to a
    /// 500 here and nowhere else.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_concurrent_publish_loser_gets_conflict() {
        let test_db = postgres_helpers::postgres_connection().await;
        assert_concurrent_publish_loser_gets_conflict(
            postgres_helpers::connect_to_test_db(&test_db.url, 1).await,
            postgres_helpers::connect_to_test_db(&test_db.url, 1).await,
            postgres_helpers::connect_to_test_db(&test_db.url, 2).await,
            "issuer-race-txn-postgres",
            "list-race-txn-postgres",
            "Postgres",
        )
        .await;
    }

    /// Blocks until at least `expected` sessions are waiting on a lock.
    ///
    /// Used instead of a fixed sleep: contention tests must interleave two
    /// sessions, and a sleep that expires early silently asserts something
    /// other than what the test claims.
    #[cfg(feature = "postgres-tests")]
    async fn await_blocked_sessions(db: &DatabaseConnection, expected: i64) {
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let blocked = db
                .query_one(Statement::from_string(
                    DatabaseBackend::Postgres,
                    "SELECT count(*) AS blocked FROM pg_stat_activity \
                 WHERE datname = current_database() \
                   AND wait_event_type = 'Lock'",
                ))
                .await
                .expect("failed to inspect pg_stat_activity")
                .expect("count(*) always returns a row")
                .try_get::<i64>("", "blocked")
                .expect("failed to read blocked-session count");

            if blocked >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected} blocked session(s); saw {blocked}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Forces a real MySQL `1205` (`ER_LOCK_WAIT_TIMEOUT`) to exercise the
    /// `SqlxMySqlError` downcast, since that error type cannot be constructed
    /// outside its own crate.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_lock_wait_timeout_maps_to_contention() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;

        let conn_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;

        // Both pools are pinned to a single connection, so this session setting
        // sticks to the connection B actually uses. Without it B would wait out
        // InnoDB's 50s default and the test would hang rather than fail.
        conn_b
            .execute_unprepared("SET SESSION innodb_lock_wait_timeout = 1")
            .await
            .expect("failed to shorten B's lock wait");

        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

        let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
        let issuer = "issuer-lockwait-mysql";
        let cred_store = SeaOrmStore::<Credentials>::new(Arc::new(
            mysql_helpers::connect_to_test_db(&test_db.url, 1).await,
        ));
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let list_id = "list-lockwait-mysql";
        let base = fixtures::record(list_id, issuer, "initial", "sub-lockwait-mysql", v);
        SeaOrmStore::<StatusListRecord>::from_handle(cred_store.db.clone())
            .insert_one(base.clone())
            .await
            .unwrap();

        // A takes an exclusive row lock and holds it, uncommitted.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "UPDATE status_lists SET sub = 'locked-by-a' WHERE list_id = ?",
                vec![Value::from(list_id)],
            ))
            .await
            .expect("A failed to take the row lock");

        // B's guard is valid — the row really is still at `v`. B fails purely
        // because it cannot acquire the lock within its 1s budget, which is what
        // makes this contention rather than a lost race.
        let result = store_b
            .update_one(
                list_id,
                StatusListRecord {
                    status_list: StatusList {
                        bits: 1,
                        lst: "writer-b".to_string(),
                    },
                    updated_at: v + 1,
                    ..base.clone()
                },
                v,
            )
            .await;

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "1205" })),
            "MySQL 1205 must classify as Contention (409) reporting its own \
         error number, not an opaque UpdateError (500); got {result:?}"
        );

        txn_a.rollback().await.expect("failed to release A's lock");
    }

    /// Credential registration is a pinned write too, and reaches the client as
    /// `409 write_contention` via `CredentialError`, not `StatusListError`.
    #[cfg(feature = "mysql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mysql_credential_insert_contention_is_classified() {
        let test_db = mysql_helpers::MysqlTestDb::start().await;

        let conn_a = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = mysql_helpers::connect_to_test_db(&test_db.url, 1).await;
        conn_b
            .execute_unprepared("SET SESSION innodb_lock_wait_timeout = 1")
            .await
            .expect("failed to shorten B's lock wait");

        let issuer = "issuer-contention-credential";
        let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();

        // A holds the primary-key entry uncommitted, so B's insert of the same
        // issuer blocks on it rather than failing fast as a duplicate.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                "INSERT INTO credentials (issuer, public_key) VALUES (?, ?)",
                vec![
                    Value::from(issuer),
                    Value::from(serde_json::to_value(&key).unwrap()),
                ],
            ))
            .await
            .expect("A failed to claim the issuer key");

        let store_b = SeaOrmStore::<Credentials>::new(Arc::new(conn_b));
        let result = store_b
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await;

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "1205" })),
            "a blocked credential insert must classify as Contention, not \
         DuplicateEntry or an opaque InsertError; got {result:?}"
        );

        txn_a.rollback().await.expect("failed to release A's lock");
    }

    /// Forces a real Postgres `40P01` (`deadlock_detected`), the only way to
    /// exercise the `SqlxPostgresError` downcast. B is chosen as the deadlock
    /// victim by giving it a shorter `deadlock_timeout` than A; A's narrower
    /// window is closed by committing B's rollback that releases the row lock.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_deadlock_maps_to_contention() {
        use std::time::Duration;

        let test_db = postgres_helpers::postgres_connection().await;
        let conn_a = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;
        let conn_b = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;

        // Victim selection. Both pools are pinned to one connection, so a
        // session-scoped setting sticks to the session that uses it.
        conn_a
            .execute_unprepared("SET SESSION deadlock_timeout = '30s'")
            .await
            .expect("failed to lengthen A's deadlock timeout");
        conn_b
            .execute_unprepared("SET SESSION deadlock_timeout = '2s'")
            .await
            .expect("failed to shorten B's deadlock timeout");

        let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

        let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
        let issuer = "issuer-deadlock-postgres";
        let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
        cred_store
            .insert_one(Credentials::new(issuer.to_string(), key))
            .await
            .unwrap();

        let v = 1000;
        let list_id = "deadlock-row";
        let snapshot_id = "snap-deadlock";
        let base = fixtures::record(list_id, issuer, "initial", "sub-deadlock", v);
        SeaOrmStore::<StatusListRecord>::new(test_db.db.clone())
            .insert_one(base.clone())
            .await
            .unwrap();

        // A claims the snapshot's primary key and holds it uncommitted, so B's
        // history insert will block on it.
        let txn_a = conn_a.begin().await.expect("failed to begin A");
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "INSERT INTO status_list_history \
             (snapshot_id, list_id, issuer, status_list, sub, iat, exp) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
                vec![
                    Value::from(snapshot_id),
                    Value::from(list_id),
                    Value::from(issuer),
                    Value::from(serde_json::json!({ "bits": 1, "lst": "a" })),
                    Value::from("sub-deadlock"),
                    Value::from(v),
                    Value::from(v + 900),
                ],
            ))
            .await
            .expect("A failed to claim the snapshot key");

        // B takes the row lock, then blocks on A's snapshot key.
        let b_call = tokio::spawn(async move {
            store_b
                .update_one_with_snapshot(
                    list_id,
                    StatusListRecord {
                        status_list: StatusList {
                            bits: 1,
                            lst: "writer-b".to_string(),
                        },
                        updated_at: v + 1,
                        ..base
                    },
                    v,
                    StatusListHistoryRecord {
                        snapshot_id: snapshot_id.to_string(),
                        list_id: list_id.to_string(),
                        issuer: issuer.to_string(),
                        status_list: StatusList {
                            bits: 1,
                            lst: "writer-b".to_string(),
                        },
                        sub: "sub-deadlock".to_string(),
                        iat: v + 1,
                        exp: v + 901,
                    },
                )
                .await
        });

        // B must hold the row lock before A closes the cycle, or A waits on a
        // lock B has not taken yet and the test hangs for real.
        await_blocked_sessions(&test_db.db, 1).await;

        // A closes the cycle. Blocks until B is rolled back as the victim, whose
        // rollback releases the row lock A is waiting on.
        txn_a
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "UPDATE status_lists SET sub = 'a' WHERE list_id = $1",
                vec![Value::from(list_id)],
            ))
            .await
            .expect("A must acquire the row lock once B is rolled back as the deadlock victim");

        let result = tokio::time::timeout(Duration::from_secs(30), b_call)
            .await
            .expect("timed out waiting for B")
            .expect("B panicked");

        assert!(
            matches!(result, Err(RepositoryError::Contention { code: "40P01" })),
            "Postgres 40P01 must classify as Contention (409) reporting its own \
         SQLSTATE, not an opaque error (500); got {result:?}"
        );
    }

    /// Verifies both write paths (`update_one` and `update_one_with_snapshot`)
    /// pin to READ COMMITTED: a racing write committed underneath an in-flight
    /// guarded update degrades to a clean guard miss (`Ok(false)`), never a
    /// `40001` serialization failure.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_postgres_pinned_isolation_downgrades_serialization_failure() {
        use std::time::Duration;

        for with_snapshot in [false, true] {
            let test_db = postgres_helpers::postgres_connection().await;
            let conn_a = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;
            let conn_b = postgres_helpers::connect_to_test_db(&test_db.url, 1).await;

            conn_b
                .execute_unprepared(
                    "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                )
                .await
                .expect("failed to raise B's isolation level");

            let store_b = SeaOrmStore::<StatusListRecord>::new(Arc::new(conn_b));

            let key: Jwk = serde_json::from_str(fixtures::TEST_EC_JWK).unwrap();
            let issuer = "issuer-pinned-postgres";
            let cred_store = SeaOrmStore::<Credentials>::new(test_db.db.clone());
            cred_store
                .insert_one(Credentials::new(issuer.to_string(), key))
                .await
                .unwrap();

            let v = 1000;
            let list_id = "pinned-row";
            let base = fixtures::record(list_id, issuer, "initial", "sub-pinned", v);
            SeaOrmStore::<StatusListRecord>::new(test_db.db.clone())
                .insert_one(base.clone())
                .await
                .unwrap();

            let txn_a = conn_a.begin().await.expect("failed to begin A");
            txn_a
                .execute(Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    "UPDATE status_lists SET sub = 'a', updated_at = $1 WHERE list_id = $2",
                    vec![Value::from(v + 5), Value::from(list_id)],
                ))
                .await
                .expect("A failed to take the row lock");

            let updated = StatusListRecord {
                status_list: StatusList {
                    bits: 1,
                    lst: "writer-b".to_string(),
                },
                updated_at: v + 1,
                ..base
            };
            let b_call = tokio::spawn(async move {
                if with_snapshot {
                    store_b
                        .update_one_with_snapshot(
                            list_id,
                            updated,
                            v,
                            StatusListHistoryRecord {
                                snapshot_id: "snap-pinned".to_string(),
                                list_id: list_id.to_string(),
                                issuer: issuer.to_string(),
                                status_list: StatusList {
                                    bits: 1,
                                    lst: "writer-b".to_string(),
                                },
                                sub: "sub-pinned".to_string(),
                                iat: v + 1,
                                exp: v + 901,
                            },
                        )
                        .await
                } else {
                    store_b.update_one(list_id, updated, v).await
                }
            });

            // Block until B is actually waiting on A's row lock, so A's commit
            // lands underneath an in-flight statement rather than before one.
            await_blocked_sessions(&test_db.db, 1).await;
            txn_a.commit().await.expect("A failed to commit");

            let result = tokio::time::timeout(Duration::from_secs(30), b_call)
                .await
                .expect("timed out waiting for B")
                .expect("B panicked");

            assert!(
                matches!(result, Ok(false)),
                "the pinned transaction must see A's committed stamp and report a \
             clean guard miss; a serialization failure here means the pin was \
             lost and the session default leaked in. \
             with_snapshot={with_snapshot}, got {result:?}"
            );
        }
    }
}
