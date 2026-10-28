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
            Box::new(issuer_aggregations::Migration),
            Box::new(issuer_ownership::Migration),
            Box::new(hosted_issuers::Migration),
            Box::new(issuer_keys::Migration),
            Box::new(issuer_audit_events::Migration),
            Box::new(issuer_keys_carry_over::Migration),
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
    "issuer_audit_events",
    "issuer_keys",
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
pub(crate) mod issuer_aggregations {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261020_000001_issuer_aggregations"
        }
    }

    const INDEX: &str = "idx_issuer_aggregations_aggregation_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_table("issuer_aggregations").await? {
                let mut table = Table::create();
                table
                    .table(IssuerAggregations::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IssuerAggregations::Issuer)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IssuerAggregations::AggregationId)
                            .string_len(36)
                            .not_null(),
                    );
                manager.create_table(table).await?;
            }
            if !manager.has_index("issuer_aggregations", INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(INDEX)
                            .table(IssuerAggregations::Table)
                            .col(IssuerAggregations::AggregationId)
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
    enum IssuerAggregations {
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

    async fn rename_issuer_aggregations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let has_old = manager.has_table("issuer_aggregations").await?;
        let has_new = manager.has_table("issuers").await?;
        match (has_old, has_new) {
            (true, false) => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE issuer_aggregations RENAME TO issuers")
                    .await?;
                if manager
                    .has_index("issuers", "idx_issuer_aggregations_aggregation_id")
                    .await?
                {
                    manager
                        .drop_index(
                            Index::drop()
                                .name("idx_issuer_aggregations_aggregation_id")
                                .table(Issuers::Table)
                                .to_owned(),
                        )
                        .await?;
                }
                Ok(())
            }
            (false, true) => Ok(()),
            (true, true) => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        "INSERT INTO issuers (issuer, aggregation_id) \
                         SELECT old.issuer, old.aggregation_id FROM issuer_aggregations old \
                         WHERE NOT EXISTS (SELECT 1 FROM issuers existing WHERE existing.issuer = old.issuer)",
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared("DROP TABLE issuer_aggregations")
                    .await
                    .map(|_| ())
            }
            (false, false) => Err(DbErr::Migration(
                "neither issuer_aggregations nor issuers exists".into(),
            )),
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            validate_aggregation_id_collisions(manager).await?;
            rename_issuer_aggregations(manager).await?;
            ensure_issuers_use_innodb(manager).await?;
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

            if !manager
                .has_index("issuers", "idx_issuers_aggregation_id")
                .await?
            {
                manager
                    .create_index(
                        Index::create()
                            .unique()
                            .name("idx_issuers_aggregation_id")
                            .table(Issuers::Table)
                            .col(Issuers::AggregationId)
                            .to_owned(),
                    )
                    .await?;
            }

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

        let backend = connection.get_database_backend();
        let sql = match backend {
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
        let stmt = Statement::from_sql_and_values(backend, sql, [source.into(), target.into()]);
        Ok(!connection.query_all_raw(stmt).await?.is_empty())
    }

    async fn ensure_issuers_use_innodb(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::{ConnectionTrait, FromQueryResult, Statement};

        if manager.get_database_backend() != sea_orm::DatabaseBackend::MySql {
            return Ok(());
        }

        #[derive(FromQueryResult)]
        struct TableEngine {
            engine: String,
        }

        let connection = manager.get_connection();
        let engine = TableEngine::find_by_statement(Statement::from_string(
            sea_orm::DatabaseBackend::MySql,
            "SELECT ENGINE AS engine FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'issuers'",
        ))
        .one(connection)
        .await?
        .ok_or_else(|| {
            DbErr::Migration("issuers table was not found after the ownership rename".into())
        })?;

        if !engine.engine.eq_ignore_ascii_case("InnoDB") {
            connection
                .execute_unprepared("ALTER TABLE issuers ENGINE=InnoDB")
                .await?;
        }
        Ok(())
    }

    async fn validate_aggregation_id_collisions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use sea_orm::{ConnectionTrait, FromQueryResult, Statement};

        #[derive(FromQueryResult)]
        struct Collision {
            credential_issuer: String,
            owner_issuer: String,
            credential_aggregation_id: String,
            owner_aggregation_id: String,
        }

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let mut collisions = Vec::new();
        for owner_table in ["issuer_aggregations", "issuers"] {
            if !manager.has_table(owner_table).await? {
                continue;
            }
            let sql = format!(
                "SELECT c.issuer AS credential_issuer, a.issuer AS owner_issuer, \
                 c.aggregation_id AS credential_aggregation_id, \
                 a.aggregation_id AS owner_aggregation_id \
                 FROM credentials c JOIN {owner_table} a \
                 ON (c.aggregation_id = a.aggregation_id AND c.issuer <> a.issuer) \
                 OR (c.issuer = a.issuer AND c.aggregation_id <> a.aggregation_id) \
                 WHERE c.aggregation_id IS NOT NULL AND a.aggregation_id IS NOT NULL"
            );
            collisions.extend(
                Collision::find_by_statement(Statement::from_string(backend, sql))
                    .all(db)
                    .await?,
            );
        }
        if collisions.is_empty() {
            return Ok(());
        }
        let details = collisions
            .into_iter()
            .map(|c| {
                if c.credential_issuer == c.owner_issuer {
                    format!(
                        "issuer {} has credentials aggregation ID {} but issuer aggregation ID {}",
                        c.credential_issuer, c.credential_aggregation_id, c.owner_aggregation_id
                    )
                } else {
                    format!(
                        "aggregation ID {} is assigned to credentials issuer {} and issuer {}",
                        c.credential_aggregation_id, c.credential_issuer, c.owner_issuer
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(DbErr::Migration(format!(
            "aggregation ID conflicts must be repaired before issuer ownership migration: {details}"
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

/// Adds the hosted-profile metadata columns to the issuer ownership record
/// (`issuers`, ADR 0002 hosted profile) rather than introducing a second
/// ownership model: a portal issuer *is* an `issuers` row, created before it
/// can publish, keyed by its server-assigned UUID in the `issuer` column.
/// Managed columns carry defaults so rows created by the registry path or by
/// credential registration keep loading untouched.
pub(crate) mod hosted_issuers {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261023_000001_hosted_issuers"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            for (column, kind) in [
                ("display_name", "TEXT NULL"),
                ("source", "VARCHAR(32) NOT NULL DEFAULT 'registry'"),
                ("tier", "VARCHAR(32) NOT NULL DEFAULT 'standard'"),
                ("state", "VARCHAR(32) NOT NULL DEFAULT 'active'"),
                ("owner", "TEXT NULL"),
                ("created_at", "BIGINT NOT NULL DEFAULT 0"),
                ("expires_at", "BIGINT NULL"),
                ("version", "BIGINT NOT NULL DEFAULT 0"),
            ] {
                if manager.has_column("issuers", column).await? {
                    continue;
                }
                manager
                    .get_connection()
                    .execute_unprepared(&format!("ALTER TABLE issuers ADD COLUMN {column} {kind}"))
                    .await?;
            }
            Ok(())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }
}

/// Hosted-profile issuer public keys; `kid` is the PK used to resolve JWTs.
/// `key_material` holds a SHA-256 of the canonical key parameters (RFC 7638
/// §7) and is uniquely indexed so key-material reuse is rejected by a
/// database constraint, not a race-prone application scan.
pub(crate) mod issuer_keys {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261023_000002_issuer_keys"
        }
    }

    const FK: &str = "fk_issuer_keys_issuer";
    const KEY_MATERIAL_INDEX: &str = "idx_issuer_keys_key_material";
    const ISSUER_ID_INDEX: &str = "idx_issuer_keys_issuer_id";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_table("issuer_keys").await? {
                let mut table = Table::create();
                table
                    .table(IssuerKeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IssuerKeys::Kid)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IssuerKeys::IssuerId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(IssuerKeys::KeyMaterial)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(ColumnDef::new(IssuerKeys::Alg).string().not_null())
                    .col(ColumnDef::new(IssuerKeys::Jwk).json().not_null())
                    .col(ColumnDef::new(IssuerKeys::State).string().not_null())
                    .col(ColumnDef::new(IssuerKeys::NotBefore).big_integer().null())
                    .col(ColumnDef::new(IssuerKeys::NotAfter).big_integer().null())
                    .col(
                        ColumnDef::new(IssuerKeys::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name(FK)
                            .from(IssuerKeys::Table, IssuerKeys::IssuerId)
                            .to(IssuersFk::Table, IssuersFk::Issuer)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    );
                pin_innodb_on_mysql(manager, &mut table);
                manager.create_table(table).await?;
            }
            // The table is created empty, so the unique index is added in the
            // same migration; folding it in avoids a later migration that adds
            // a UNIQUE index over a defaulted column that may already have rows.
            if !manager.has_index("issuer_keys", KEY_MATERIAL_INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(KEY_MATERIAL_INDEX)
                            .table(IssuerKeys::Table)
                            .col(IssuerKeys::KeyMaterial)
                            .unique()
                            .to_owned(),
                    )
                    .await?;
            }
            // Listing an issuer's keys and the `ON DELETE CASCADE` scan this
            // column; Postgres does not index FK columns automatically.
            if !manager.has_index("issuer_keys", ISSUER_ID_INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(ISSUER_ID_INDEX)
                            .table(IssuerKeys::Table)
                            .col(IssuerKeys::IssuerId)
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

    // Local Iden view of the ownership table's PK for the FK target; the
    // canonical `Issuers` enum is scoped to the ownership migration.
    #[derive(Iden)]
    enum IssuersFk {
        #[iden = "issuers"]
        Table,
        Issuer,
    }

    #[derive(Iden)]
    enum IssuerKeys {
        Table,
        Kid,
        IssuerId,
        KeyMaterial,
        Alg,
        Jwk,
        State,
        NotBefore,
        NotAfter,
        CreatedAt,
    }
}

/// Append-only audit of hosted-profile issuer changes; no FK so it survives
/// issuer removal. `id` is a UUID to avoid backend-specific auto-increment.
pub(crate) mod issuer_audit_events {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261023_000003_issuer_audit_events"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if !manager.has_table("issuer_audit_events").await? {
                let mut table = Table::create();
                table
                    .table(IssuerAuditEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IssuerAuditEvents::Id)
                            .string_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IssuerAuditEvents::IssuerId)
                            .string_len(255)
                            .null(),
                    )
                    .col(ColumnDef::new(IssuerAuditEvents::Actor).string().null())
                    .col(
                        ColumnDef::new(IssuerAuditEvents::Action)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(IssuerAuditEvents::Before).json().null())
                    .col(ColumnDef::new(IssuerAuditEvents::After).json().null())
                    .col(
                        ColumnDef::new(IssuerAuditEvents::CreatedAt)
                            .big_integer()
                            .not_null(),
                    );
                pin_innodb_on_mysql(manager, &mut table);
                manager.create_table(table).await?;
            }
            // Audit queries filter by issuer; the table is created empty in the
            // same migration, so this index ships before any rows exist.
            if !manager.has_index("issuer_audit_events", INDEX).await? {
                manager
                    .create_index(
                        Index::create()
                            .name(INDEX)
                            .table(IssuerAuditEvents::Table)
                            .col(IssuerAuditEvents::IssuerId)
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

    const INDEX: &str = "idx_issuer_audit_events_issuer_id";

    #[derive(Iden)]
    enum IssuerAuditEvents {
        Table,
        Id,
        IssuerId,
        Actor,
        Action,
        Before,
        After,
        CreatedAt,
    }
}

/// Carries every usable `credentials` key into `issuer_keys` unchanged, so
/// issuers keep the kid they chose. The material hash is computed in Rust
/// because it needs base64url decoding and zero stripping, which portable SQL
/// cannot do.
///
/// Carried issuers get `source = 'credential'`, which the hosted key lookup
/// accepts and `find_issuer` does not: they resolve by key, but are not portal
/// issuers. Issuers whose aggregation ID is still NULL are assigned one, so
/// the carried key does not resolve to a corrupt row.
///
/// Only registry-backed credentials are carried (`source = 'registry'`): a
/// credential someone attaches to a portal issuer's id must not be picked up.
///
/// Idempotent: a row already carried identically is skipped, so a re-run after
/// a partial MySQL failure resumes. Carried keys land `reserved`, so they hold
/// the kid and material but authenticate nothing until an operator adopts the
/// key into the registry. Data conflicts never fail the migration: rows whose
/// material is shared by several credentials, and rows that would collide with
/// an existing `issuer_keys` row, are skipped with a warning. Only real
/// database errors return `Err`.
pub(crate) mod issuer_keys_carry_over {
    use super::*;
    use crate::domain::models::credential::{PublicJwk, canonical_jwk_material};
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261024_000001_issuer_keys_carry_over"
        }
    }

    /// The `issuers.source` of an issuer whose keys came from `credentials`.
    pub(crate) const CARRIED_SOURCE: &str = "credential";

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            carry_over_credential_keys(manager.get_connection())
                .await
                .map(|_| ())
        }

        async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
            refuse_down(self.name())
        }
    }

    struct Planned {
        issuer: String,
        kid: String,
        hash: String,
        alg: &'static str,
        jwk_json: String,
        needs_aggregation_id: bool,
    }

    fn ph(backend: DatabaseBackend, n: usize) -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${n}")
        } else {
            "?".to_string()
        }
    }

    fn jose_alg(algorithm: jsonwebtoken::Algorithm) -> Option<&'static str> {
        use jsonwebtoken::Algorithm::*;
        match algorithm {
            ES256 => Some("ES256"),
            ES384 => Some("ES384"),
            EdDSA => Some("EdDSA"),
            PS256 => Some("PS256"),
            _ => None,
        }
    }

    /// The migration's private carry-over; not callable elsewhere. Runs once
    /// at upgrade; re-running it would be unsafe while credentials can still
    /// be created against an issuer's id.
    async fn carry_over_credential_keys<C: ConnectionTrait>(conn: &C) -> Result<usize, DbErr> {
        let backend = conn.get_database_backend();
        let rows = conn
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT c.issuer AS issuer, c.public_key AS public_key, c.key_id AS key_id, \
                     i.aggregation_id AS aggregation_id \
                     FROM credentials c JOIN issuers i ON i.issuer = c.issuer \
                     WHERE c.key_id IS NOT NULL AND i.source = 'registry' \
                     ORDER BY c.issuer",
            ))
            .await?;

        let mut candidates = Vec::new();
        for row in rows {
            let issuer: String = row.try_get("", "issuer")?;
            let kid: String = row.try_get("", "key_id")?;
            let public_key: serde_json::Value = row.try_get("", "public_key")?;
            let aggregation_id: Option<String> = row.try_get("", "aggregation_id")?;

            let bytes = serde_json::to_vec(&public_key)
                .map_err(|e| DbErr::Migration(format!("credential `{issuer}`: {e}")))?;
            let jwk = match PublicJwk::try_new(bytes) {
                Ok(jwk) if jwk.key_id() == kid => jwk,
                Ok(_) => {
                    tracing::warn!(%issuer, %kid, "skipping credential key: JWK kid differs from key_id");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%issuer, %kid, %error, "skipping credential key: not a valid management key");
                    continue;
                }
            };
            let Some(alg) = jose_alg(jwk.algorithm()) else {
                continue;
            };
            let material = canonical_jwk_material(&public_key)
                .map_err(|e| DbErr::Migration(format!("credential `{issuer}`: {e}")))?;
            let hash = hex::encode(Sha256::digest(material.as_bytes()));
            candidates.push(Planned {
                issuer,
                kid,
                hash,
                alg,
                jwk_json: jwk_to_string(&jwk)?,
                needs_aggregation_id: aggregation_id.is_none(),
            });
        }

        // Skip every credential whose material is shared by several
        // credentials: their ownership is ambiguous, so none is carried.
        let mut counts = BTreeMap::<String, usize>::new();
        for candidate in &candidates {
            *counts.entry(candidate.hash.clone()).or_default() += 1;
        }
        let (shared, plan): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .partition(|candidate| counts[&candidate.hash] > 1);
        for candidate in &shared {
            tracing::warn!(
                issuer = %candidate.issuer,
                kid = %candidate.kid,
                "not carrying credential key: its key material is shared by several credentials"
            );
        }

        // Skip any remaining row that would collide with an existing
        // `issuer_keys` row it is not identical to. Data conflicts must not
        // fail the upgrade; only real database errors do.
        let lookup = format!(
            "SELECT kid, issuer_id, key_material FROM issuer_keys WHERE kid = {} OR key_material = {}",
            ph(backend, 1),
            ph(backend, 2)
        );
        let mut already = Vec::new();
        let mut carrying = Vec::new();
        for planned in plan {
            let existing = conn
                .query_all_raw(Statement::from_sql_and_values(
                    backend,
                    &lookup,
                    [planned.kid.clone().into(), planned.hash.clone().into()],
                ))
                .await?;
            let mut identical = false;
            let mut skip = false;
            for row in existing {
                let kid: String = row.try_get("", "kid")?;
                let issuer_id: String = row.try_get("", "issuer_id")?;
                let hash: String = row.try_get("", "key_material")?;
                if kid == planned.kid && issuer_id == planned.issuer && hash == planned.hash {
                    identical = true;
                } else {
                    tracing::warn!(
                        issuer = %planned.issuer,
                        kid = %planned.kid,
                        existing_kid = %kid,
                        existing_issuer = %issuer_id,
                        "not carrying credential key: it collides with an existing issuer key"
                    );
                    skip = true;
                }
            }
            if !skip {
                already.push(identical);
                carrying.push(planned);
            }
        }

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let jwk_value = if backend == DatabaseBackend::Postgres {
            "CAST($5 AS JSON)".to_string()
        } else {
            "?".to_string() // CAST(? AS JSON) would give SQLite a numeric affinity.
        };
        let insert = format!(
            "INSERT INTO issuer_keys \
                 (kid, issuer_id, key_material, alg, jwk, state, not_before, not_after, created_at) \
                 VALUES ({}, {}, {}, {}, {jwk_value}, 'reserved', NULL, NULL, {})",
            ph(backend, 1),
            ph(backend, 2),
            ph(backend, 3),
            ph(backend, 4),
            ph(backend, 6)
        );
        let mut carried = 0;
        for (planned, skip) in carrying.iter().zip(already) {
            if planned.needs_aggregation_id {
                conn.execute_raw(Statement::from_sql_and_values(
                        backend,
                        format!(
                            "UPDATE issuers SET aggregation_id = {} WHERE issuer = {} AND aggregation_id IS NULL",
                            ph(backend, 1),
                            ph(backend, 2)
                        ),
                        [
                            uuid::Uuid::new_v4().to_string().into(),
                            planned.issuer.clone().into(),
                        ],
                    ))
                    .await?;
            }
            if skip {
                continue;
            }
            conn.execute_raw(Statement::from_sql_and_values(
                backend,
                &insert,
                [
                    planned.kid.clone().into(),
                    planned.issuer.clone().into(),
                    planned.hash.clone().into(),
                    planned.alg.into(),
                    planned.jwk_json.clone().into(),
                    now.into(),
                ],
            ))
            .await?;
            conn.execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "UPDATE issuers SET source = {} WHERE issuer = {} AND source = 'registry'",
                    ph(backend, 1),
                    ph(backend, 2)
                ),
                [CARRIED_SOURCE.into(), planned.issuer.clone().into()],
            ))
            .await?;
            carried += 1;
        }
        Ok(carried)
    }

    fn jwk_to_string(jwk: &PublicJwk) -> Result<String, DbErr> {
        serde_json::to_string(jwk.jwk()).map_err(|e| DbErr::Migration(e.to_string()))
    }
}

#[cfg(all(
    test,
    any(feature = "sqlite", feature = "mysql", feature = "postgres-tests")
))]
mod carry_over_tests {
    use super::*;
    use crate::domain::models::credential::KeyResolveError;
    use crate::domain::ports::{HostedIssuerStore, IssuerKeyResolver};
    use crate::outbound::sql::SqlHostedIssuerStore;
    use crate::outbound::sql::models::{Credentials, credentials, issuers};
    use jsonwebtoken::jwk::Jwk;
    use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, Set, Statement};
    use std::sync::Arc;

    /// The release before the carry-over migration.
    struct Before;
    #[async_trait::async_trait]
    impl MigratorTrait for Before {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            let mut all = Migrator::migrations();
            all.pop();
            all
        }
    }

    const KEY_1: &str = r#"{"kty":"EC","crv":"P-256","kid":"key-1","alg":"ES256","x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8","y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}"#;
    const KEY_2: &str = r#"{"kty":"EC","crv":"P-256","kid":"key-2","alg":"ES256","x":"qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E","y":"c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"}"#;
    const OCT: &str = r#"{"kty":"oct","kid":"oct-1","alg":"HS256","k":"c2VjcmV0"}"#;
    const RSA_PS256: &str = r#"{"kty":"RSA","kid":"rsa-1","alg":"PS256","n":"uNtunrvdLa-WuK-VpCwiEUXlOCmONEmo0ZYQ424NsGns0OVnu1T9hL4M_UODdKhz-_mXHvqsBxS-PZe0OMmdo9QrGWwnS4H8IX5c_fKZ01AX21_hJoQY6SMLUVGVbElqNW032v-LliC7-dTB0YeTg_wmbAN1uGkPr202k3c_18gVGvpa8B7Ri8Ytowl6WzpiVZ3VyP3HIQQuhrAXN0B1BatWpv4GwLXr-ihCmFgbS2RHm5TIkoap2yXw2p488RFgrnacRGj9QhN4p9HIMuYeLkoeClMS2ZQD2d9holRyRCUsARh8IvSf9DZVmDGwd5kqpHqT3GkZ8o8kdGAQTq53Nw","e":"AQAB"}"#;
    /// A third distinct EC key, used only for the shared-material pair.
    const KEY_DUP: &str = r#"{"kty":"EC","crv":"P-256","kid":"dup-x","alg":"ES256","x":"w0Nc9y5IMwcWV08tC3KtnukblytlN1HTOFngG8U6d60","y":"UklyBhY4aZvUS9aJDifOAiLMj1LVwNmhA8AXRvcs3f8"}"#;
    /// A kid shaped like an RFC 7638 thumbprint, carried unchanged like any other.
    const THUMBPRINT_KID: &str = "tlBOuPIle0dk1Dbs1lKHGJS5yMXswT8QXuVO4RWwxgg";

    /// Seeds one legacy credential and its issuer row. `source` is the
    /// `issuers.source` the carry-over migration filters on.
    async fn seed(db: &DatabaseConnection, issuer: &str, kid: &str, jwk: &str, source: &str) {
        let mut key: Jwk = serde_json::from_str(jwk).unwrap();
        key.common.key_id = Some(kid.to_string());
        let issuer_row = issuers::ActiveModel {
            issuer: Set(issuer.to_string()),
            aggregation_id: Set(None),
            list_count: Set(0),
            display_name: Set(None),
            source: Set(source.to_string()),
            tier: Set("standard".to_string()),
            state: Set("active".to_string()),
            owner: Set(None),
            created_at: Set(0),
            expires_at: Set(None),
            version: Set(1),
        };
        issuers::Entity::insert(issuer_row)
            .exec_without_returning(db)
            .await
            .unwrap();
        let credential: credentials::ActiveModel = Credentials::new(issuer.to_string(), key).into();
        credentials::Entity::insert(credential)
            .exec_without_returning(db)
            .await
            .unwrap();
    }

    /// A static registry that has adopted the carried identity `legacy-1` /
    /// `key-1`, so its key now authenticates through the static-first resolver.
    fn registry_with_static_adoption() -> Arc<crate::server::auth::issuer_registry::RegistryHandle>
    {
        let jwk: serde_json::Value = serde_json::from_str(KEY_1).unwrap();
        Arc::new(
            crate::server::auth::issuer_registry::RegistryHandle::from_yaml(
                &serde_saphyr::to_string(&serde_json::json!({
                    "version": 1,
                    "issuers": [{
                        "id": "legacy-1",
                        "aggregation_id": uuid::Uuid::new_v4(),
                        "keys": [{ "kid": "key-1", "alg": "ES256", "jwk": jwk }],
                    }],
                    "admins": [],
                }))
                .unwrap(),
            )
            .unwrap(),
        )
    }

    /// The full upgrade scenario, run from an unmigrated database: an earlier
    /// release's legacy credentials are seeded, then the current migrator runs.
    /// Postgres exercises the `$n` numbering and `CAST($5 AS JSON)`; on MySQL a
    /// partial failure leaves partial inserts, so the idempotency check matters
    /// there too.
    async fn upgrade_scenario(db: Arc<DatabaseConnection>) {
        let backend = db.get_database_backend();
        apply_migrations::<Before>(db.as_ref()).await.unwrap();

        seed(&db, "legacy-1", "key-1", KEY_1, "registry").await; // human-chosen EC kid
        seed(
            &db,
            "legacy-thumb",
            THUMBPRINT_KID,
            &KEY_2.replace("key-2", THUMBPRINT_KID),
            "registry",
        )
        .await; // thumbprint kid
        seed(&db, "legacy-rsa", "rsa-1", RSA_PS256, "registry").await; // RSA key
        seed(&db, "legacy-oct", "oct-1", OCT, "registry").await; // oct: not a valid management key
        seed(
            &db,
            "dup-a",
            "dup-a",
            &KEY_DUP.replace("dup-x", "dup-a"),
            "registry",
        )
        .await; // shared material
        seed(
            &db,
            "dup-b",
            "dup-b",
            &KEY_DUP.replace("dup-x", "dup-b"),
            "registry",
        )
        .await; // shared material
        // A credential attached to a portal issuer's id must not be carried.
        seed(&db, "portal-issuer", "portal-key", KEY_2, "portal").await;

        run_migrations(&db).await.unwrap();

        // Carried kids: key-1, the thumbprint kid, and rsa-1. The oct key, the
        // shared-material duplicates, and the portal-attached key are skipped.
        let rows = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT kid, state FROM issuer_keys ORDER BY kid",
            ))
            .await
            .unwrap();
        let mut kids: Vec<String> = rows.iter().map(|r| r.try_get("", "kid").unwrap()).collect();
        let mut expected = vec![
            "key-1".to_string(),
            THUMBPRINT_KID.to_string(),
            "rsa-1".to_string(),
        ];
        expected.sort();
        kids.sort();
        assert_eq!(kids, expected, "carried kids on {backend:?}");
        let states: Vec<String> = rows
            .iter()
            .map(|r| r.try_get("", "state").unwrap())
            .collect();
        assert!(
            states.iter().all(|state| state == "reserved"),
            "carried keys must land reserved on {backend:?}: {states:?}"
        );

        // A NULL-aggregation-id issuer was assigned one so its carried key does
        // not resolve to a corrupt row.
        let agg = db
            .query_one_raw(Statement::from_string(
                backend,
                "SELECT aggregation_id FROM issuers WHERE issuer = 'legacy-1'",
            ))
            .await
            .unwrap()
            .expect("legacy-1 must exist")
            .try_get::<Option<String>>("", "aggregation_id")
            .unwrap();
        assert!(
            agg.is_some(),
            "NULL aggregation id must be assigned on {backend:?}"
        );

        // A reserved carried key must never authenticate, until adopted.
        let store: Arc<dyn HostedIssuerStore> = Arc::new(SqlHostedIssuerStore::new(db.clone()));
        let resolver = crate::server::auth::hosted::CompositeIssuerKeyResolver::new(
            Arc::new(crate::server::auth::issuer_registry::RegistryHandle::empty()),
            Some(store.clone()),
        );
        assert!(
            matches!(
                resolver.resolve("key-1").await,
                Err(KeyResolveError::Reserved)
            ),
            "a reserved carried key must not authenticate on {backend:?}"
        );
        let resolver = crate::server::auth::hosted::CompositeIssuerKeyResolver::new(
            registry_with_static_adoption(),
            Some(store),
        );
        let resolved = resolver.resolve("key-1").await.unwrap();
        assert_eq!(resolved.principal.id(), "legacy-1");

        // Idempotency: re-running the carry-over migration is a no-op (this is
        // what a partial MySQL failure resumes from).
        issuer_keys_carry_over::Migration
            .up(&SchemaManager::new(db.as_ref()))
            .await
            .unwrap();
        let rows_after = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT kid FROM issuer_keys ORDER BY kid",
            ))
            .await
            .unwrap();
        assert_eq!(
            rows_after.len(),
            kids.len(),
            "a re-run must not change rows on {backend:?}"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_carry_over_upgrade_scenario() {
        use sea_orm::{ConnectOptions, Database};
        let mut options = ConnectOptions::new("sqlite::memory:");
        options
            .max_connections(1)
            .map_sqlx_sqlite_opts(|o| o.foreign_keys(true));
        let db = Database::connect(options).await.unwrap();
        upgrade_scenario(Arc::new(db)).await;
    }

    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn mysql_carry_over_upgrade_scenario() {
        use crate::outbound::sql::test_containers::mysql_helpers;
        let test_db = mysql_helpers::MysqlTestDb::start_unmigrated().await;
        upgrade_scenario(test_db.connection().await).await;
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn postgres_carry_over_upgrade_scenario() {
        use crate::outbound::sql::test_containers::postgres_helpers;
        let test_db = postgres_helpers::postgres_connection_unmigrated().await;
        upgrade_scenario(test_db.db.clone()).await;
    }
}
