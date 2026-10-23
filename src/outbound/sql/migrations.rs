//! Database migrations for the SeaORM adapter.

use sea_orm_migration::prelude::*;

/// Main migrator struct for database migrations
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(tables::Migration),
            Box::new(add_updated_at::Migration),
            Box::new(status_list_history::Migration),
            Box::new(status_list_history_exp_index::Migration),
            Box::new(credentials_list_count::Migration),
            Box::new(list_quota::Migration),
            Box::new(status_list_allocations::Migration),
            Box::new(add_status_list_version::Migration),
            Box::new(add_status_list_history_version::Migration),
            Box::new(credentials_aggregation_id::Migration),
            Box::new(status_lists_issuer_list_id_index::Migration),
            Box::new(credentials_key_id::Migration),
            Box::new(issuers::Migration),
            Box::new(issuer_ownership::Migration),
        ]
    }

    /// Drops every table without running any `down`, so it is refused with them.
    async fn fresh<'c, C>(_db: C) -> Result<(), DbErr>
    where
        C: IntoSchemaManagerConnection<'c>,
    {
        Err(forward_only("dropping every table is refused"))
    }
}

/// Applies pending migrations; returns whether none had been applied before.
pub async fn run_migrations(db: &sea_orm::DatabaseConnection) -> Result<bool, DbErr> {
    apply_migrations::<Migrator>(db).await
}

/// [`run_migrations`] for any migrator, so tests can stand in for an earlier
/// release with a migrator that knows only the first migrations.
pub(crate) async fn apply_migrations<M: MigratorTrait>(
    db: &sea_orm::DatabaseConnection,
) -> Result<bool, DbErr> {
    let applied = async {
        let fresh = M::get_applied_migrations(db).await?.is_empty();
        M::up(db, None).await?;
        Ok(fresh)
    }
    .await;
    match applied {
        Ok(fresh) => Ok(fresh),
        Err(err) => Err(name_unknown_migrations::<M>(db, err).await),
    }
}

/// After migrating failed, names the migrations the database records that `M`
/// does not know: what stops a rolled-back release from starting. Returns
/// `err` unchanged when there are none or the records cannot be read, so it
/// never stops a start that would otherwise have succeeded.
async fn name_unknown_migrations<M: MigratorTrait>(
    db: &sea_orm::DatabaseConnection,
    err: DbErr,
) -> DbErr {
    let Ok(records) = M::get_migration_models(db).await else {
        return err;
    };
    let known: Vec<String> = M::migrations()
        .iter()
        .map(|migration| migration.name().to_owned())
        .collect();
    let unknown: Vec<String> = records
        .into_iter()
        .map(|record| record.version)
        .filter(|version| !known.contains(version))
        .collect();
    if unknown.is_empty() {
        return err;
    }
    DbErr::Migration(format!(
        "the database records migrations this release does not know: {}. A newer release \
         migrated it, and this release cannot start until those records are deleted. Check \
         that each is safe to leave in place, then follow \"{ROLLBACK_RUNBOOK_SECTION}\" in \
         docs/deployment-runbook.md. ({err})",
        unknown.join(", ")
    ))
}

/// Recomputes every issuer's ownership-record list count and is quoted verbatim
/// in `docs/troubleshooting.md` as the operator repair.
pub(crate) const RECOUNT_LIST_COUNT_SQL: &str = "UPDATE issuers SET list_count = \
     (SELECT COUNT(*) FROM status_lists WHERE status_lists.issuer = issuers.issuer)";
const BACKFILL_CREDENTIAL_LIST_COUNT_SQL: &str = "UPDATE credentials SET list_count = \
     (SELECT COUNT(*) FROM status_lists WHERE status_lists.issuer = credentials.issuer)";

/// Pins InnoDB on MySQL so `update_with_snapshot`'s UPDATE+INSERT roll back as a
/// unit rather than depending on the server's default engine. MySQL-only:
/// sea-query renders the engine option as a literal `ENGINE=InnoDB` clause on
/// every backend, which SQLite and Postgres reject with a syntax error.
fn pin_innodb_on_mysql(manager: &SchemaManager<'_>, stmt: &mut TableCreateStatement) {
    if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        stmt.engine("InnoDB");
    }
}

/// The `docs/deployment-runbook.md` section the refusals and the startup error
/// point at.
const ROLLBACK_RUNBOOK_SECTION: &str = "Rolling back across migrations";

/// Every migration's `down`: the schema only moves forward. See "Migrations
/// are forward-only" in `src/outbound/sql/README.md`.
fn refuse_down(migration: &str) -> Result<(), DbErr> {
    Err(forward_only(&format!(
        "migration '{migration}' cannot be rolled back"
    )))
}

/// The refusal every path back returns, naming what was refused.
fn forward_only(refused: &str) -> DbErr {
    DbErr::Migration(format!(
        "{refused}: the schema only moves forward. To roll back a release, delete the \
         seaql_migrations records of the migrations it does not know and keep the schema; \
         see \"{ROLLBACK_RUNBOOK_SECTION}\" in docs/deployment-runbook.md"
    ))
}

/// Tables that must use InnoDB for transactional guarantees and foreign key enforcement.
/// Extend this list if new transactional tables are added.
const INNODB_REQUIRED_TABLES: &[&str] = &[
    "credentials",
    "issuers",
    "status_lists",
    "status_list_history",
    "status_list_allocations",
    "list_quota",
];

/// Queries `information_schema.TABLES` after migrations and refuses to boot if
/// any of the tables in `INNODB_REQUIRED_TABLES` are not
/// InnoDB. MyISAM silently ignores transactions, so a non-InnoDB install breaks
/// the guarantees from issue #244 without any visible error.
///
/// No-op on Postgres and SQLite. On failure the error log includes the table
/// name, its actual engine, and the `ALTER TABLE … ENGINE=InnoDB` fix command.
pub(crate) async fn verify_innodb_engines(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm::{FromQueryResult, Statement, Value};

    if db.get_database_backend() != sea_orm::DatabaseBackend::MySql {
        return Ok(());
    }

    #[derive(Debug, FromQueryResult)]
    struct TableEngine {
        #[sea_orm(from_alias = "TABLE_NAME")]
        table_name: String,
        #[sea_orm(from_alias = "ENGINE")]
        engine: String,
    }

    // Build `IN (?, ?, …)` from the const table list so the query stays in
    // sync with INNODB_REQUIRED_TABLES without manual string editing.
    let placeholders = INNODB_REQUIRED_TABLES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT TABLE_NAME AS table_name, ENGINE AS engine \
         FROM information_schema.TABLES \
         WHERE table_schema = DATABASE() \
           AND table_name IN ({placeholders})"
    );
    let values: Vec<Value> = INNODB_REQUIRED_TABLES.iter().map(|t| (*t).into()).collect();

    let rows = TableEngine::find_by_statement(Statement::from_sql_and_values(
        sea_orm::DatabaseBackend::MySql,
        sql,
        values,
    ))
    .all(db)
    .await?;

    let table_pairs: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r.table_name.as_str(), r.engine.as_str()))
        .collect();

    evaluate_table_engines(table_pairs)
}

/// Refuses to boot a MySQL deployment whose binary logging is incompatible with
/// the READ COMMITTED level the store pins on every write.
///
/// InnoDB at READ COMMITTED requires row-based binary logging. Under
/// `binlog_format = STATEMENT` writes fail with error 1665
/// (`ER_BINLOG_STMT_MODE_AND_ROW_ENGINE`) — an opaque 500 at first publish, on a
/// server that started up cleanly. `ROW` and `MIXED` are both fine, and 8.0
/// defaults to `ROW`, so this only fires where `STATEMENT` was set deliberately.
///
/// No-op on PostgreSQL and SQLite.
pub(crate) async fn verify_binlog_format(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm::{FromQueryResult, Statement};

    if db.get_database_backend() != sea_orm::DatabaseBackend::MySql {
        return Ok(());
    }

    #[derive(Debug, FromQueryResult)]
    struct BinlogFormat {
        #[sea_orm(from_alias = "binlog_format")]
        binlog_format: String,
    }

    let row = BinlogFormat::find_by_statement(Statement::from_string(
        sea_orm::DatabaseBackend::MySql,
        "SELECT @@GLOBAL.binlog_format AS binlog_format",
    ))
    .one(db)
    .await?;

    // A server built without binary logging exposes no such variable, and has no
    // replication to be incompatible with. Absence is a pass.
    let Some(row) = row else {
        return Ok(());
    };

    evaluate_binlog_format(&row.binlog_format)
}

/// Decision half of [`verify_binlog_format`], testable without a live server.
pub(crate) fn evaluate_binlog_format(format: &str) -> Result<(), DbErr> {
    use tracing::error;

    if !format.eq_ignore_ascii_case("STATEMENT") {
        return Ok(());
    }

    error!(
        binlog_format = %format,
        "MySQL is configured with binlog_format=STATEMENT, which InnoDB cannot \
         combine with the READ COMMITTED isolation level this server pins on \
         every write. Writes would fail with error 1665 \
         (ER_BINLOG_STMT_MODE_AND_ROW_ENGINE). To fix, set binlog_format=ROW \
         (or MIXED) on the server and restart it."
    );

    Err(DbErr::Custom(format!(
        "MySQL binlog_format is '{format}'; InnoDB at READ COMMITTED requires \
         ROW or MIXED binary logging"
    )))
}

/// Evaluates storage engines for required tables and returns an error if any non-InnoDB engine is found.
pub(crate) fn evaluate_table_engines<'a, I>(rows: I) -> Result<(), DbErr>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    use tracing::error;

    let mut non_innodb: Vec<(&str, &str)> = Vec::new();
    for (table_name, engine) in rows {
        if !engine.eq_ignore_ascii_case("InnoDB") {
            error!(
                table = %table_name,
                engine = %engine,
                "Table '{table_name}' has storage engine '{engine}' instead of InnoDB. \
                 InnoDB is required for transactional guarantees (see issue #244). \
                 To fix, run during a maintenance window: \
                 ALTER TABLE `{table_name}` ENGINE=InnoDB;"
            );
            non_innodb.push((table_name, engine));
        }
    }

    if non_innodb.is_empty() {
        Ok(())
    } else {
        let details = non_innodb
            .iter()
            .map(|(t, e)| format!("{t}({e})"))
            .collect::<Vec<_>>()
            .join(", ");
        let alter_commands = non_innodb
            .iter()
            .map(|(t, _)| format!("ALTER TABLE `{t}` ENGINE=InnoDB;"))
            .collect::<Vec<_>>()
            .join(" ");
        Err(DbErr::Custom(format!(
            "Non-InnoDB tables detected: {details}. \
             The server requires InnoDB for transactional guarantees. \
             To fix, run in a maintenance window: {alter_commands}",
        )))
    }
}

pub(crate) mod tables {
    use super::*;

    /// Migration type for creating database tables
    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "mod"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        /// Creates the necessary database tables if they don't exist
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // Credentials table. InnoDB is pinned on MySQL (see
            // `pin_innodb_on_mysql`) so the FK below is enforced there.
            let mut credentials = Table::create();
            credentials
                .table(Credentials::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Credentials::Issuer)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Credentials::PublicKey).json().not_null());
            pin_innodb_on_mysql(manager, &mut credentials);
            manager.create_table(credentials).await?;

            // StatusLists table; InnoDB pinned on MySQL (see above).
            let mut status_lists = Table::create();
            status_lists
                .table(StatusLists::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(StatusLists::ListId)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(StatusLists::Issuer).string().not_null())
                .col(ColumnDef::new(StatusLists::StatusList).json().not_null())
                .col(ColumnDef::new(StatusLists::Sub).string().not_null())
                .foreign_key(
                    // FK: StatusLists.Issuer must reference a valid Credentials.Issuer.
                    ForeignKey::create()
                        .name("fk_status_lists_issuer")
                        .from(StatusLists::Table, StatusLists::Issuer)
                        .to(Credentials::Table, Credentials::Issuer)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                );
            pin_innodb_on_mysql(manager, &mut status_lists);
            manager.create_table(status_lists).await?;

            // Create an index on list_id for faster lookups
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_status_lists_list_id")
                        .table(StatusLists::Table)
                        .col(StatusLists::ListId)
                        .to_owned(),
                )
                .await?;

            // Create index on issuer for faster lookups
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_status_lists_issuer")
                        .table(StatusLists::Table)
                        .col(StatusLists::Issuer)
                        .to_owned(),
                )
                .await?;

            // Create index on sub for faster lookups in find_by_issuer
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_status_lists_sub")
                        .table(StatusLists::Table)
                        .col(StatusLists::Sub)
                        .to_owned(),
                )
                .await?;

            Ok(())
        }

        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum Credentials {
        Table,
        Issuer,
        PublicKey,
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        ListId,
        Issuer,
        StatusList,
        Sub,
    }
}

/// Migration to add updated_at column to status_lists table
pub(crate) mod add_updated_at {
    use super::*;

    /// Migration type for adding updated_at column
    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "add_updated_at"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        /// Adds updated_at column to status_lists table
        #[allow(elided_lifetimes_in_paths)]
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(StatusLists::Table)
                        .add_column(
                            ColumnDef::new(StatusLists::UpdatedAt)
                                .big_integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;

            // Backfill pre-existing rows. With default(0) every legacy row
            // would report Last-Modified = 1970-01-01, so any
            // If-Modified-Since date >= 1970 would yield 304 and fresh
            // tokens would never be served via the IMS path until the first
            // update touches the row. Setting them to the migration run
            // time makes the validator meaningful immediately.
            let now_secs = time::OffsetDateTime::now_utc().unix_timestamp();
            let update_stmt = sea_query::Query::update()
                .table(StatusLists::Table)
                .value(StatusLists::UpdatedAt, now_secs)
                .to_owned();
            manager
                .get_connection()
                .execute_raw(manager.get_database_backend().build(&update_stmt))
                .await
                .map(|_| ())
        }

        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        UpdatedAt,
    }
}

/// Migration to add a monotonic optimistic-concurrency `version` column to
/// `status_lists`, decoupled from the `updated_at` timestamp.
///
/// Before this change, `updated_at` doubled as both the real last-modification
/// timestamp and the optimistic-concurrency guard (`next_updated_at` advanced it
/// by at least one per write). That let a burst of writes to a single list push
/// `updated_at` — and therefore the served token's `iat` — ahead of the wall
/// clock, which relying parties that reject a future `iat` would refuse. This
/// column splits the two concerns: the monotonic `version` becomes the
/// concurrency guard and cache-fencing stamp, while `updated_at` stays a real
/// timestamp.
pub(crate) mod add_status_list_version {
    use super::*;

    /// Migration type for adding the version column
    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "add_status_list_version"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        /// Adds the version column to the status_lists table.
        #[allow(elided_lifetimes_in_paths)]
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // A re-run after a rollback finds the column already there.
            if !manager.has_column("status_lists", "version").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(StatusLists::Table)
                            .add_column(
                                ColumnDef::new(StatusLists::Version)
                                    .big_integer()
                                    .not_null()
                                    .default(1),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            // No backfill: DEFAULT 1 fills existing rows, and a re-run must not reset versions.
            Ok(())
        }

        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        Version,
    }
}

/// Adds the `version` tie-breaker to `status_list_history`.
///
/// Two updates to the same list within the same second share an `iat` (since
/// `updated_at` is a real wall-clock timestamp), so `?time=` resolution could
/// otherwise return the pre-change snapshot. The monotonic optimistic-concurrency
/// `version` recorded on the snapshot breaks that tie: `find_valid_at` orders by
/// `iat DESC, version DESC` so the post-change snapshot wins.
pub(crate) mod add_status_list_history_version {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "add_status_list_history_version"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_column("status_list_history", "version").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(StatusListHistory::Table)
                            .add_column(
                                ColumnDef::new(StatusListHistory::Version)
                                    .big_integer()
                                    .not_null()
                                    .default(0),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusListHistory {
        Table,
        Version,
    }
}

/// Historical Status List Token payloads used for draft-21 §8.4 queries.
pub(crate) mod status_list_history {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20250101_000003_status_list_history"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // InnoDB pinned on MySQL (see `pin_innodb_on_mysql`) so a failing
            // snapshot INSERT rolls the paired row UPDATE back.
            let mut history = Table::create();
            history
                .table(StatusListHistory::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(StatusListHistory::SnapshotId)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(StatusListHistory::ListId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(StatusListHistory::Issuer)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(StatusListHistory::StatusList)
                        .json()
                        .not_null(),
                )
                .col(ColumnDef::new(StatusListHistory::Sub).string().not_null())
                .col(
                    ColumnDef::new(StatusListHistory::Iat)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(StatusListHistory::Exp)
                        .big_integer()
                        .not_null(),
                );
            pin_innodb_on_mysql(manager, &mut history);
            manager.create_table(history).await?;
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_status_list_history_resolution")
                        .table(StatusListHistory::Table)
                        .col(StatusListHistory::ListId)
                        .col(StatusListHistory::Iat)
                        .col(StatusListHistory::Exp)
                        .to_owned(),
                )
                .await
        }

        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusListHistory {
        Table,
        SnapshotId,
        ListId,
        Issuer,
        StatusList,
        Sub,
        Iat,
        Exp,
    }
}

/// Migration to add an index on `exp` for the retention sweep query.
pub(crate) mod status_list_history_exp_index {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260727_000001_status_list_history_exp_index"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_status_list_history_exp")
                        .table(StatusListHistory::Table)
                        .col(StatusListHistory::Exp)
                        .to_owned(),
                )
                .await
        }

        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    // Intentionally redefined in this migration module to be self-contained.
    // See `status_list_history::Migration` for the full table definition.
    #[derive(Iden)]
    enum StatusListHistory {
        Table,
        Exp,
    }
}

/// Migration adding the per-issuer list counter behind `limits.max_lists_per_issuer`.
pub(crate) mod credentials_list_count {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260923_000001_credentials_list_count"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // MySQL commits the ALTER on its own, so a failed backfill leaves the
            // column behind with the migration unrecorded; the re-run must skip it.
            if !manager.has_column("credentials", "list_count").await? {
                // DEFAULT 0 lets pods on the previous release keep inserting
                // credentials during a rolling deploy.
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credentials::Table)
                            .add_column(
                                ColumnDef::new(Credentials::ListCount)
                                    .big_integer()
                                    .not_null()
                                    .default(0),
                            )
                            .to_owned(),
                    )
                    .await?;
            }

            // Old pods keep publishing uncounted; `list-quota recount` fixes that.
            manager
                .get_connection()
                .execute_unprepared(BACKFILL_CREDENTIAL_LIST_COUNT_SQL)
                .await
                .map(|_| ())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum Credentials {
        Table,
        ListCount,
    }
}

/// The switch for `limits.max_lists_per_issuer`, off until `list_quota::on_startup`
/// or `list-quota enable` turns it on.
pub(crate) mod list_quota {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260923_000002_list_quota"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // InnoDB for the row locks `list_quota` relies on.
            let mut table = Table::create();
            table
                .table(ListQuota::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(ListQuota::Id)
                        .integer()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ListQuota::Enforced)
                        .boolean()
                        .not_null()
                        .default(false),
                );
            pin_innodb_on_mysql(manager, &mut table);
            manager.create_table(table).await?;

            // MySQL commits the CREATE on its own, so a re-run may find the row.
            let db = manager.get_connection();
            let backend = manager.get_database_backend();
            let existing = db
                .query_one_raw(
                    backend.build(
                        Query::select()
                            .column(ListQuota::Id)
                            .from(ListQuota::Table)
                            .and_where(Expr::col(ListQuota::Id).eq(ROW_ID)),
                    ),
                )
                .await?;
            if existing.is_none() {
                db.execute_raw(
                    backend.build(
                        Query::insert()
                            .into_table(ListQuota::Table)
                            .columns([ListQuota::Id, ListQuota::Enforced])
                            .values_panic([ROW_ID.into(), false.into()]),
                    ),
                )
                .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    const ROW_ID: i32 = crate::outbound::sql::list_quota::ROW_ID;

    #[derive(Iden)]
    enum ListQuota {
        Table,
        Id,
        Enforced,
    }
}

/// Allocated status-list indices. The composite primary key is the durable
/// guard against double allocation of a `(list_id, idx)` pair.
pub(crate) mod status_list_allocations {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260925_000001_status_list_allocations"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            let mut table = Table::create();
            table
                .table(StatusListAllocations::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(StatusListAllocations::ListId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(StatusListAllocations::Idx)
                        .integer()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(StatusListAllocations::ListId)
                        .col(StatusListAllocations::Idx),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_status_list_allocations_list_id")
                        .from(StatusListAllocations::Table, StatusListAllocations::ListId)
                        .to(StatusLists::Table, StatusLists::ListId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                );
            pin_innodb_on_mysql(manager, &mut table);
            manager.create_table(table).await
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusListAllocations {
        Table,
        ListId,
        Idx,
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        ListId,
    }
}

/// Migration adding the opaque per-issuer ID that aggregation URIs carry.
pub(crate) mod credentials_aggregation_id {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260929_000001_credentials_aggregation_id"
        }
    }

    const INDEX: &str = "idx_credentials_aggregation_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // Nullable so pods on the previous release keep registering during a
            // rolling deploy; the first lookup of such a row fills it in. Each
            // step is guarded because MySQL commits DDL on its own, so a failed
            // run is re-run.
            if !manager.has_column("credentials", "aggregation_id").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credentials::Table)
                            .add_column(
                                ColumnDef::new(Credentials::AggregationId)
                                    .string_len(36)
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            if !manager.has_index("credentials", INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(INDEX)
                            .table(Credentials::Table)
                            .col(Credentials::AggregationId)
                            .unique()
                            .to_owned(),
                    )
                    .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum Credentials {
        Table,
        AggregationId,
    }
}

/// Stores and uniquely indexes the JWK `kid` used to resolve management tokens without
/// scanning and deserializing the complete credential registry per request.
pub(crate) mod credentials_key_id {
    use super::*;
    use sea_orm::{ConnectionTrait, Statement};

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261014_000001_credentials_key_id"
        }
    }

    const INDEX: &str = "idx_credentials_key_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_column("credentials", "key_id").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credentials::Table)
                            .add_column(ColumnDef::new(Credentials::KeyId).string_len(255).null())
                            .to_owned(),
                    )
                    .await?;
            }

            let backfill = match manager.get_database_backend() {
                sea_orm::DatabaseBackend::Postgres => {
                    "UPDATE credentials SET key_id = CASE WHEN jsonb_typeof(public_key::jsonb -> 'kid') = 'string' AND length(public_key ->> 'kid') <= 255 THEN public_key ->> 'kid' ELSE NULL END WHERE key_id IS NULL"
                }
                sea_orm::DatabaseBackend::MySql => {
                    "UPDATE credentials SET key_id = CASE WHEN JSON_TYPE(JSON_EXTRACT(public_key, '$.kid')) = 'STRING' AND CHAR_LENGTH(JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.kid'))) <= 255 THEN JSON_UNQUOTE(JSON_EXTRACT(public_key, '$.kid')) ELSE NULL END WHERE key_id IS NULL"
                }
                sea_orm::DatabaseBackend::Sqlite => {
                    "UPDATE credentials SET key_id = CASE WHEN json_type(public_key, '$.kid') = 'text' AND length(json_extract(public_key, '$.kid')) <= 255 THEN json_extract(public_key, '$.kid') ELSE NULL END WHERE key_id IS NULL"
                }
                backend => {
                    return Err(DbErr::Migration(format!(
                        "unsupported database backend for credential kid migration: {backend:?}"
                    )));
                }
            };
            manager
                .get_connection()
                .execute_unprepared(backfill)
                .await?;

            // Legacy credentials without a kid get an RFC 7638 SHA-256 public
            // JWK thumbprint. Preserve every supplied ID and signing algorithm.
            // Update JSON and its indexed copy in one statement, so retries can
            // never leave those two representations out of sync.
            let connection = manager.get_connection();
            let backend = manager.get_database_backend();
            let rows = connection
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT issuer, public_key FROM credentials WHERE key_id IS NULL",
                ))
                .await?;
            let mut pending = Vec::new();
            let mut owners = std::collections::BTreeMap::<String, Vec<String>>::new();
            for row in rows {
                let issuer: String = row.try_get("", "issuer")?;
                let mut public_key: serde_json::Value = row.try_get("", "public_key")?;
                let Some(kid) = missing_key_id(&public_key) else {
                    continue;
                };
                public_key["kid"] = kid.clone().into();
                owners.entry(kid.clone()).or_default().push(issuer.clone());
                pending.push((issuer, public_key, kid));
            }

            // Check the complete plan before writing any generated IDs. Let the
            // database compare existing IDs so MySQL's column collation applies.
            let lookup = match backend {
                sea_orm::DatabaseBackend::Postgres => {
                    "SELECT issuer FROM credentials WHERE key_id = $1 ORDER BY issuer"
                }
                _ => "SELECT issuer FROM credentials WHERE key_id = ? ORDER BY issuer",
            };
            let mut collisions = Vec::new();
            for (kid, issuers) in &mut owners {
                for row in connection
                    .query_all_raw(Statement::from_sql_and_values(
                        backend,
                        lookup,
                        [kid.clone().into()],
                    ))
                    .await?
                {
                    issuers.push(row.try_get("", "issuer")?);
                }
                if issuers.len() > 1 {
                    issuers.sort();
                    collisions.push(format!("kid {kid:?}: issuers {issuers:?}"));
                }
            }
            if !collisions.is_empty() {
                return Err(DbErr::Migration(format!(
                    "credential key ID backfill collisions; repair these registrations before retrying: {}",
                    collisions.join("; ")
                )));
            }

            for (issuer, public_key, kid) in pending {
                let update = match backend {
                    sea_orm::DatabaseBackend::Postgres => {
                        "UPDATE credentials SET public_key = CAST($1 AS JSONB), key_id = $2 WHERE issuer = $3 AND key_id IS NULL"
                    }
                    _ => {
                        "UPDATE credentials SET public_key = ?, key_id = ? WHERE issuer = ? AND key_id IS NULL"
                    }
                };
                connection
                    .execute_raw(Statement::from_sql_and_values(
                        backend,
                        update,
                        [public_key.to_string().into(), kid.into(), issuer.into()],
                    ))
                    .await?;
            }

            if !manager.has_index("credentials", INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(INDEX)
                            .table(Credentials::Table)
                            .col(Credentials::KeyId)
                            .unique()
                            .to_owned(),
                    )
                    .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    fn missing_key_id(public_key: &serde_json::Value) -> Option<String> {
        use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, ThumbprintHash};
        let object = public_key.as_object()?;
        if object.get("kid").is_some_and(|kid| !kid.is_null())
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|name| object.contains_key(*name))
        {
            return None;
        }
        let jwk: Jwk = serde_json::from_value(public_key.clone()).ok()?;
        if matches!(
            jwk.algorithm,
            AlgorithmParameters::OctetKey(_) | AlgorithmParameters::Other(_)
        ) {
            return None;
        }
        jsonwebtoken::DecodingKey::from_jwk(&jwk).ok()?;
        jwk.thumbprint(ThumbprintHash::SHA256).ok()
    }

    #[derive(Iden)]
    enum Credentials {
        Table,
        KeyId,
    }
}

/// Migration indexing `status_lists` by `(issuer, list_id)`, so an issuer-scoped
/// aggregation page is a range scan. Postgres and SQLite indexes on `issuer`
/// alone do not carry `list_id`, which would read and sort all of an issuer's
/// lists for every page.
pub(crate) mod status_lists_issuer_list_id_index {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260929_000002_status_lists_issuer_list_id_index"
        }
    }

    const INDEX: &str = "idx_status_lists_issuer_list_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if manager.has_index("status_lists", INDEX).await? {
                return Ok(());
            }
            manager
                .create_index(
                    Index::create()
                        .name(INDEX)
                        .table(StatusLists::Table)
                        .col(StatusLists::Issuer)
                        .col(StatusLists::ListId)
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        Issuer,
        ListId,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_innodb_table_is_flagged() {
        let rows = [
            ("credentials", "InnoDB"),
            ("status_lists", "MyISAM"),
            ("status_list_history", "InnoDB"),
        ];
        let result = evaluate_table_engines(rows);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();

        assert!(
            err_msg.contains("status_lists(MyISAM)"),
            "must name affected table and engine"
        );
        assert!(
            err_msg.contains("ALTER TABLE `status_lists` ENGINE=InnoDB;"),
            "must include ALTER TABLE fix command"
        );
        assert!(
            !err_msg.contains("credentials"),
            "InnoDB table must not appear in error"
        );
        assert!(
            !err_msg.contains("status_list_history"),
            "InnoDB table must not appear in error"
        );
    }

    #[test]
    fn all_innodb_produces_no_error() {
        let rows = [
            ("credentials", "InnoDB"),
            ("status_lists", "InnoDB"),
            ("status_list_history", "InnoDB"),
        ];
        assert!(evaluate_table_engines(rows).is_ok());
    }

    #[test]
    fn engine_comparison_is_case_insensitive() {
        for variant in ["innodb", "INNODB", "InnoDB", "Innodb"] {
            let rows = [("status_lists", variant)];
            assert!(evaluate_table_engines(rows).is_ok());
        }
    }

    #[tokio::test]
    async fn verify_innodb_engines_skips_non_mysql_backends() {
        use sea_orm::{DatabaseBackend, MockDatabase};

        for backend in [DatabaseBackend::Sqlite, DatabaseBackend::Postgres] {
            let db = MockDatabase::new(backend).into_connection();
            let result = verify_innodb_engines(&db).await;
            assert!(result.is_ok(), "must skip non-MySQL backend {backend:?}");
        }
    }

    #[test]
    fn statement_binlog_format_is_rejected() {
        for variant in ["STATEMENT", "statement", "Statement"] {
            let err = evaluate_binlog_format(variant)
                .expect_err("binlog_format=STATEMENT is incompatible with READ COMMITTED");
            assert!(
                err.to_string().contains(variant),
                "the refusal must name the offending value; got {err}"
            );
        }
    }

    /// `MIXED` promotes these statements to row format, so rejecting it would
    /// refuse to boot a valid deployment.
    #[test]
    fn row_and_mixed_binlog_formats_are_accepted() {
        for variant in ["ROW", "row", "MIXED", "mixed"] {
            assert!(
                evaluate_binlog_format(variant).is_ok(),
                "binlog_format={variant} is compatible and must not block startup"
            );
        }
    }

    #[test]
    fn recount_sql_is_quoted_verbatim_in_the_runbook() {
        let runbook = include_str!("../../../docs/troubleshooting.md");
        assert!(
            runbook.contains(RECOUNT_LIST_COUNT_SQL),
            "docs/troubleshooting.md must quote RECOUNT_LIST_COUNT_SQL verbatim"
        );
    }

    #[test]
    fn refuse_down_names_a_runbook_section_that_exists() {
        let runbook = include_str!("../../../docs/deployment-runbook.md");
        assert!(
            runbook.contains(&format!("### {ROLLBACK_RUNBOOK_SECTION}")),
            "docs/deployment-runbook.md must have the section refuse_down names"
        );
    }

    #[test]
    fn every_migration_has_a_row_in_the_runbook_table() {
        let runbook = include_str!("../../../docs/deployment-runbook.md");
        for migration in Migrator::migrations() {
            let name = migration.name();
            assert!(
                runbook.contains(&format!("| `{name}` |")),
                "docs/deployment-runbook.md must say whether {name} is safe to leave in place"
            );
        }
    }

    #[tokio::test]
    async fn verify_binlog_format_skips_non_mysql_backends() {
        use sea_orm::{DatabaseBackend, MockDatabase};

        for backend in [DatabaseBackend::Sqlite, DatabaseBackend::Postgres] {
            let db = MockDatabase::new(backend).into_connection();
            let result = verify_binlog_format(&db).await;
            assert!(result.is_ok(), "must skip non-MySQL backend {backend:?}");
        }
    }
}

/// Persists the `aggregation_id` of issuers that exist only in the operator
/// trust registry (no `credentials` row, so no `public_key`). The mapping must
/// survive pod restarts and be shared across pods so an issuer's published
/// aggregation URI cannot silently change.
pub(crate) mod issuers {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261020_000001_issuer_aggregations"
        }
    }

    const INDEX: &str = "idx_issuers_aggregation_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_table("issuers").await? {
                let mut table = Table::create();
                table
                    .table(Issuers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Issuers::Issuer)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Issuers::AggregationId)
                            .string_len(36)
                            .not_null(),
                    );
                pin_innodb_on_mysql(manager, &mut table);
                manager.create_table(table).await?;
            }
            if !manager.has_index("issuers", INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(INDEX)
                            .table(Issuers::Table)
                            .col(Issuers::AggregationId)
                            .unique()
                            .to_owned(),
                    )
                    .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    #[derive(Iden)]
    enum Issuers {
        #[iden = "issuers"]
        Table,
        Issuer,
        AggregationId,
    }
}

/// Makes the durable aggregation mapping the owner and quota record for every
/// issuer, including issuers that have no aggregation ID yet.
pub(crate) mod issuer_ownership {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261022_000001_issuer_ownership"
        }
    }

    const SQLITE_CREATE_STATUS_LISTS: &str = "CREATE TABLE status_lists_new (\
        list_id TEXT NOT NULL PRIMARY KEY, issuer TEXT NOT NULL, \
        status_list JSON NOT NULL, sub TEXT NOT NULL, \
        updated_at BIGINT NOT NULL DEFAULT 0, version BIGINT NOT NULL DEFAULT 1, \
        CONSTRAINT fk_status_lists_issuer_issuers \
        FOREIGN KEY (issuer) REFERENCES issuers(issuer) \
        ON DELETE RESTRICT ON UPDATE RESTRICT\
    )";
    const SQLITE_COPY_STATUS_LISTS: &str = "INSERT INTO status_lists_new \
        (list_id, issuer, status_list, sub, updated_at, version) \
        SELECT list_id, issuer, status_list, sub, updated_at, version FROM status_lists";
    const SQLITE_STATUS_LIST_INDEXES: [&str; 4] = [
        "CREATE INDEX IF NOT EXISTS idx_status_lists_list_id ON status_lists (list_id)",
        "CREATE INDEX IF NOT EXISTS idx_status_lists_issuer ON status_lists (issuer)",
        "CREATE INDEX IF NOT EXISTS idx_status_lists_sub ON status_lists (sub)",
        "CREATE INDEX IF NOT EXISTS idx_status_lists_issuer_list_id ON status_lists (issuer, list_id)",
    ];
    const SQLITE_CREATE_CREDENTIALS: &str = "CREATE TABLE credentials_new (\
        issuer TEXT NOT NULL PRIMARY KEY, public_key JSON NOT NULL, key_id VARCHAR(255) NULL, \
        list_count BIGINT NOT NULL DEFAULT 0, aggregation_id VARCHAR(36) NULL, \
        CONSTRAINT fk_credentials_issuer_issuers \
        FOREIGN KEY (issuer) REFERENCES issuers(issuer) \
        ON DELETE RESTRICT ON UPDATE RESTRICT\
    )";
    const SQLITE_COPY_CREDENTIALS: &str = "INSERT INTO credentials_new \
        (issuer, public_key, key_id, list_count, aggregation_id) \
        SELECT issuer, public_key, key_id, list_count, aggregation_id FROM credentials";
    const SQLITE_CREDENTIAL_INDEXES: [&str; 2] = [
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_key_id ON credentials (key_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_aggregation_id ON credentials (aggregation_id)",
    ];
    const SQLITE_CREATE_ISSUERS: &str = "CREATE TABLE issuers_new (\
        issuer TEXT NOT NULL PRIMARY KEY, aggregation_id VARCHAR(36) NULL, \
        list_count BIGINT NOT NULL DEFAULT 0\
    )";
    const SQLITE_COPY_ISSUERS: &str = "INSERT INTO issuers_new \
        (issuer, aggregation_id, list_count) \
        SELECT issuer, aggregation_id, list_count FROM issuers";
    const SQLITE_ISSUER_INDEX: &str =
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_issuers_aggregation_id ON issuers (aggregation_id)";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            validate_aggregation_id_collisions(manager).await?;
            if !manager.has_column("issuers", "list_count").await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Issuers::Table)
                            .add_column(
                                ColumnDef::new(Issuers::ListCount)
                                    .big_integer()
                                    .not_null()
                                    .default(0),
                            )
                            .to_owned(),
                    )
                    .await?;
            }

            if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
                if sqlite_column_is_not_null(manager, "issuers", "aggregation_id").await? {
                    rebuild_sqlite_issuers(manager).await?;
                }
            } else {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Issuers::Table)
                            .modify_column(
                                ColumnDef::new(Issuers::AggregationId).string_len(36).null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }

            manager
                .get_connection()
                .execute_unprepared(
                    "INSERT INTO issuers (issuer, aggregation_id, list_count) \
                     SELECT c.issuer, c.aggregation_id, c.list_count FROM credentials c \
                     WHERE NOT EXISTS (SELECT 1 FROM issuers a WHERE a.issuer = c.issuer)",
                )
                .await?;
            manager
                .get_connection()
                .execute_unprepared(RECOUNT_LIST_COUNT_SQL)
                .await?;

            if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
                if !foreign_key_references_table(manager, "credentials", "issuers").await? {
                    rebuild_sqlite_credentials(manager).await?;
                }
            } else if !foreign_key_references_table(manager, "credentials", "issuers").await? {
                manager
                    .create_foreign_key(
                        ForeignKey::create()
                            .name("fk_credentials_issuer_issuers")
                            .from(Credentials::Table, Credentials::Issuer)
                            .to(Issuers::Table, Issuers::Issuer)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Restrict)
                            .to_owned(),
                    )
                    .await?;
            }

            let owns_lists =
                foreign_key_references_table(manager, "status_lists", "issuers").await?;
            let references_credentials =
                foreign_key_references_table(manager, "status_lists", "credentials").await?;
            if manager.get_database_backend() == sea_orm::DatabaseBackend::Sqlite {
                if references_credentials || !manager.has_table("status_lists").await? {
                    rebuild_sqlite_status_lists(manager).await?;
                }
            } else {
                if references_credentials {
                    manager
                        .drop_foreign_key(
                            ForeignKey::drop()
                                .table(StatusLists::Table)
                                .name("fk_status_lists_issuer")
                                .to_owned(),
                        )
                        .await?;
                }
                if !owns_lists {
                    manager
                        .create_foreign_key(
                            ForeignKey::create()
                                .name("fk_status_lists_issuer_issuers")
                                .from(StatusLists::Table, StatusLists::Issuer)
                                .to(Issuers::Table, Issuers::Issuer)
                                .on_delete(ForeignKeyAction::Restrict)
                                .on_update(ForeignKeyAction::Restrict)
                                .to_owned(),
                        )
                        .await?;
                }
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    async fn foreign_key_references_table(
        manager: &SchemaManager<'_>,
        source: &str,
        target: &str,
    ) -> Result<bool, DbErr> {
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

        let connection = manager.get_connection();
        if connection.get_database_backend() == DatabaseBackend::Sqlite {
            return Ok(connection
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA foreign_key_list({source})"),
                ))
                .await?
                .iter()
                .any(|row| {
                    row.try_get::<String>("", "table")
                        .is_ok_and(|table| table == target)
                }));
        }

        let sql = match connection.get_database_backend() {
            DatabaseBackend::MySql => "SELECT 1 FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND REFERENCED_TABLE_NAME = ?".to_owned(),
            DatabaseBackend::Postgres => "SELECT 1 FROM information_schema.key_column_usage kcu \
                 JOIN information_schema.constraint_column_usage ccu \
                 ON kcu.constraint_catalog = ccu.constraint_catalog \
                 AND kcu.constraint_schema = ccu.constraint_schema \
                 AND kcu.constraint_name = ccu.constraint_name \
                 WHERE kcu.table_schema = current_schema() AND kcu.table_name = $1 \
                 AND ccu.table_name = $2".to_owned(),
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "foreign_key_references",
                });
            }
        };
        let stmt = match connection.get_database_backend() {
            DatabaseBackend::MySql => Statement::from_sql_and_values(
                DatabaseBackend::MySql,
                sql,
                [source.into(), target.into()],
            ),
            DatabaseBackend::Postgres => Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql,
                [source.into(), target.into()],
            ),
            _ => unreachable!(),
        };
        Ok(!connection.query_all_raw(stmt).await?.is_empty())
    }

    async fn validate_aggregation_id_collisions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::{ConnectionTrait, FromQueryResult, Statement};

        #[derive(FromQueryResult)]
        struct Collision {
            credential_issuer: String,
            existing_issuer: String,
            aggregation_id: String,
        }

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let sql = "SELECT c.issuer AS credential_issuer, a.issuer AS existing_issuer, \
                   c.aggregation_id AS aggregation_id FROM credentials c JOIN issuers a \
                   ON c.aggregation_id = a.aggregation_id AND c.issuer <> a.issuer";
        let collisions =
            Collision::find_by_statement(Statement::from_string(backend, sql.to_owned()))
                .all(db)
                .await?;
        if collisions.is_empty() {
            return Ok(());
        }
        let details = collisions
            .into_iter()
            .map(|c| {
                format!(
                    "{} conflicts with {} for {}",
                    c.credential_issuer, c.existing_issuer, c.aggregation_id
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(DbErr::Migration(format!(
            "aggregation ID collisions must be repaired before issuer ownership migration: {details}"
        )))
    }

    async fn sqlite_column_is_not_null(
        manager: &SchemaManager<'_>,
        table: &str,
        column: &str,
    ) -> Result<bool, DbErr> {
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

        let rows = manager
            .get_connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA table_info({table})"),
            ))
            .await?;
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .is_ok_and(|name| name == column)
                && row
                    .try_get::<i64>("", "notnull")
                    .is_ok_and(|value| value != 0)
        }))
    }

    async fn sqlite_table_rebuild(
        manager: &SchemaManager<'_>,
        rebuild: impl AsyncFnOnce() -> Result<(), DbErr>,
    ) -> Result<(), DbErr> {
        use sea_orm::ConnectionTrait;
        let connection = manager.get_connection();
        // The SQLite pool is pinned to one connection so the pragma and DDL share a transaction.
        connection
            .execute_unprepared("PRAGMA foreign_keys = OFF")
            .await?;
        connection.execute_unprepared("BEGIN IMMEDIATE").await?;
        let result = rebuild().await;
        let finish = if result.is_ok() {
            connection.execute_unprepared("COMMIT").await
        } else {
            connection.execute_unprepared("ROLLBACK").await
        };
        if finish.is_err() {
            let _ = connection.execute_unprepared("ROLLBACK").await;
        }
        let restore_foreign_keys = connection
            .execute_unprepared("PRAGMA foreign_keys = ON")
            .await;
        finish?;
        restore_foreign_keys?;
        result
    }

    async fn rebuild_sqlite_status_lists(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::ConnectionTrait;
        let connection = manager.get_connection();
        sqlite_table_rebuild(manager, async || {
            if !manager.has_table("status_lists").await? {
                connection
                    .execute_unprepared("ALTER TABLE status_lists_new RENAME TO status_lists")
                    .await?;
            } else {
                connection
                    .execute_unprepared("DROP TABLE IF EXISTS status_lists_new")
                    .await?;
                connection
                    .execute_unprepared(SQLITE_CREATE_STATUS_LISTS)
                    .await?;
                connection
                    .execute_unprepared(SQLITE_COPY_STATUS_LISTS)
                    .await?;
                connection
                    .execute_unprepared("DROP TABLE status_lists")
                    .await?;
                connection
                    .execute_unprepared("ALTER TABLE status_lists_new RENAME TO status_lists")
                    .await?;
            }
            for index in SQLITE_STATUS_LIST_INDEXES {
                connection.execute_unprepared(index).await?;
            }
            Ok(())
        })
        .await
    }

    async fn rebuild_sqlite_credentials(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::ConnectionTrait;
        let connection = manager.get_connection();
        sqlite_table_rebuild(manager, async || {
            connection
                .execute_unprepared("DROP TABLE IF EXISTS credentials_new")
                .await?;
            connection
                .execute_unprepared(SQLITE_CREATE_CREDENTIALS)
                .await?;
            connection
                .execute_unprepared(SQLITE_COPY_CREDENTIALS)
                .await?;
            connection
                .execute_unprepared("DROP TABLE credentials")
                .await?;
            connection
                .execute_unprepared("ALTER TABLE credentials_new RENAME TO credentials")
                .await?;
            for index in SQLITE_CREDENTIAL_INDEXES {
                connection.execute_unprepared(index).await?;
            }
            Ok(())
        })
        .await
    }

    async fn rebuild_sqlite_issuers(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::ConnectionTrait;
        let connection = manager.get_connection();
        sqlite_table_rebuild(manager, async || {
            if !manager.has_table("issuers").await? {
                connection
                    .execute_unprepared("ALTER TABLE issuers_new RENAME TO issuers")
                    .await?;
            } else {
                connection
                    .execute_unprepared("DROP TABLE IF EXISTS issuers_new")
                    .await?;
                connection.execute_unprepared(SQLITE_CREATE_ISSUERS).await?;
                connection.execute_unprepared(SQLITE_COPY_ISSUERS).await?;
                connection.execute_unprepared("DROP TABLE issuers").await?;
                connection
                    .execute_unprepared("ALTER TABLE issuers_new RENAME TO issuers")
                    .await?;
            }
            connection.execute_unprepared(SQLITE_ISSUER_INDEX).await?;
            Ok(())
        })
        .await
    }

    #[derive(Iden)]
    enum Issuers {
        #[iden = "issuers"]
        Table,
        Issuer,
        AggregationId,
        ListCount,
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        Issuer,
    }

    #[derive(Iden)]
    enum Credentials {
        Table,
        Issuer,
    }
}
