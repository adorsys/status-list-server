use sea_orm_migration::prelude::*;

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
        ]
    }

    /// Refused along with every `down`: it drops all tables.
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

/// Generic so tests can play an older release with fewer migrations.
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

/// Names migrations the DB has but this release doesn't, the usual reason a rollback won't start.
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

/// Quoted verbatim in docs/troubleshooting.md; keep them in sync.
pub(crate) const RECOUNT_LIST_COUNT_SQL: &str = "UPDATE credentials SET list_count = \
     (SELECT COUNT(*) FROM status_lists WHERE status_lists.issuer = credentials.issuer)";

/// MySQL only: sea-query emits ENGINE=InnoDB for every backend, and the others reject it.
fn pin_innodb_on_mysql(manager: &SchemaManager<'_>, stmt: &mut TableCreateStatement) {
    if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        stmt.engine("InnoDB");
    }
}

/// Heading in docs/deployment-runbook.md.
const ROLLBACK_RUNBOOK_SECTION: &str = "Rolling back across migrations";

/// Migrations are forward-only; see src/outbound/sql/README.md.
fn refuse_down(migration: &str) -> Result<(), DbErr> {
    Err(forward_only(&format!(
        "migration '{migration}' cannot be rolled back"
    )))
}

fn forward_only(refused: &str) -> DbErr {
    DbErr::Migration(format!(
        "{refused}: the schema only moves forward. To roll back a release, delete the \
         seaql_migrations records of the migrations it does not know and keep the schema; \
         see \"{ROLLBACK_RUNBOOK_SECTION}\" in docs/deployment-runbook.md"
    ))
}

/// Add new transactional tables here.
const INNODB_REQUIRED_TABLES: &[&str] = &[
    "credentials",
    "status_lists",
    "status_list_history",
    "status_list_allocations",
    "list_quota",
];

/// MyISAM silently ignores transactions, so refuse to boot on it.
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

/// binlog_format=STATEMENT makes READ COMMITTED writes fail (1665), so catch it at boot.
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

    // No binlog variable means no binary logging, which is fine.
    let Some(row) = row else {
        return Ok(());
    };

    evaluate_binlog_format(&row.binlog_format)
}

/// Split out so it can be tested without a server.
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

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "mod"
        }
    }

    #[async_trait::async_trait]
    #[allow(elided_lifetimes_in_paths)]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                    ForeignKey::create()
                        .name("fk_status_lists_issuer")
                        .from(StatusLists::Table, StatusLists::Issuer)
                        .to(Credentials::Table, Credentials::Issuer)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                );
            pin_innodb_on_mysql(manager, &mut status_lists);
            manager.create_table(status_lists).await?;

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

pub(crate) mod add_updated_at {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "add_updated_at"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
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

            // A 0 default would answer every legacy If-Modified-Since with 304, so use now.
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

/// Splits the concurrency guard off `updated_at`, which write bursts used to push into the future.
pub(crate) mod add_status_list_version {
    use super::*;

    pub(crate) struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "add_status_list_version"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
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

/// Breaks `iat` ties between snapshots written in the same second.
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

/// For the retention sweep.
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

    // Redefined so this migration stays self-contained.
    #[derive(Iden)]
    enum StatusListHistory {
        Table,
        Exp,
    }
}

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
            // MySQL auto-commits DDL, so a re-run may find the column already there.
            if !manager.has_column("credentials", "list_count").await? {
                // DEFAULT 0 so old pods can still insert during a rolling deploy.
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
                .execute_unprepared(RECOUNT_LIST_COUNT_SQL)
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

/// Quota switch; off until `on_startup` or `list-quota enable` turns it on.
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

/// The composite primary key is what prevents double allocation.
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
            // Nullable so old pods can still register; the first lookup fills it in.
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

/// Indexes `kid` so management auth doesn't scan the whole credential registry per request.
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

            // Legacy keys without a kid get their RFC 7638 thumbprint; supplied IDs stay.
            // One statement updates the JSON and its indexed copy, so retries can't split them.
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

            // Check the whole plan before writing any ID.
            // The database does the comparing, so MySQL's column collation applies.
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

/// Lets issuer-scoped aggregation pages range-scan instead of sorting every list.
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
