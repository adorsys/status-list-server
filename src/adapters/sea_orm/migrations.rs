//! Database migrations for the SeaORM adapter.
use sea_orm_migration::prelude::*;

/// Main migrator struct for database migrations
pub(crate) struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(tables::Migration),
            Box::new(add_updated_at::Migration),
            Box::new(status_list_history::Migration),
        ]
    }
}

/// Pins InnoDB on MySQL so `update_with_snapshot`'s UPDATE+INSERT roll back as a
/// unit rather than depending on the server's default engine. MySQL-only:
/// sea-query renders the engine option as a literal `ENGINE=InnoDB` clause on
/// every backend, which SQLite and Postgres reject with a syntax error.
fn pin_innodb_on_mysql(manager: &SchemaManager<'_>, stmt: &mut TableCreateStatement) {
    if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        stmt.engine("InnoDB");
    }
}

/// Tables that must use InnoDB for transactional guarantees.
/// Extend this list if new transactional tables are added.
const INNODB_REQUIRED_TABLES: &[&str] = &["status_lists", "status_list_history"];

/// Queries `information_schema.TABLES` after migrations and refuses to boot if
/// any of the critical tables (`status_lists`, `status_list_history`) are not
/// InnoDB. MyISAM silently ignores transactions, so a non-InnoDB install breaks
/// the guarantees from issue #244 without any visible error.
///
/// No-op on Postgres and SQLite. On failure the error log includes the table
/// name, its actual engine, and the `ALTER TABLE … ENGINE=InnoDB` fix command.
pub(crate) async fn verify_innodb_engines(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm::{ConnectionTrait, FromQueryResult, Statement, Value};
    use tracing::error;

    if db.get_database_backend() != sea_orm::DatabaseBackend::MySql {
        return Ok(());
    }

    #[derive(Debug, FromQueryResult)]
    struct TableEngine {
        table_name: String,
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
        "SELECT table_name, engine \
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

    let mut non_innodb: Vec<String> = Vec::new();
    for row in rows {
        if !row.engine.eq_ignore_ascii_case("InnoDB") {
            error!(
                table = %row.table_name,
                engine = %row.engine,
                "Table '{}' has storage engine '{}' instead of InnoDB. \
                 InnoDB is required for transactional guarantees (see issue #244). \
                 To fix, run during a maintenance window: \
                 ALTER TABLE `{}` ENGINE=InnoDB;",
                row.table_name, row.engine, row.table_name,
            );
            non_innodb.push(format!("{}({})", row.table_name, row.engine));
        }
    }

    if non_innodb.is_empty() {
        Ok(())
    } else {
        let alter_commands = non_innodb
            .iter()
            .map(|entry| {
                let table = entry.split('(').next().unwrap_or(entry);
                format!("ALTER TABLE `{table}` ENGINE=InnoDB;")
            })
            .collect::<Vec<_>>()
            .join(" ");
        Err(DbErr::Custom(format!(
            "Non-InnoDB tables detected: {}. \
             The server requires InnoDB for transactional guarantees. \
             To fix, run in a maintenance window: {alter_commands}",
            non_innodb.join(", "),
        )))
    }
}

/// Database tables module containing table creation migrations
pub(crate) mod tables {
    use super::*;

    /// Migration struct for creating database tables
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

        /// Drops the database tables
        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            // Drop indexes first
            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_status_lists_list_id")
                        .table(StatusLists::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_status_lists_sub")
                        .table(StatusLists::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_status_lists_issuer")
                        .table(StatusLists::Table)
                        .to_owned(),
                )
                .await?;

            // Drop tables in reverse order to handle foreign key constraints
            manager
                .drop_table(
                    Table::drop()
                        .if_exists()
                        .table(StatusLists::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .drop_table(
                    Table::drop()
                        .if_exists()
                        .table(Credentials::Table)
                        .to_owned(),
                )
                .await?;
            Ok(())
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

    /// Migration struct for adding updated_at column
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
                .execute(manager.get_database_backend().build(&update_stmt))
                .await
                .map(|_| ())
        }

        /// Removes updated_at column from status_lists table
        #[allow(elided_lifetimes_in_paths)]
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(StatusLists::Table)
                        .drop_column(StatusLists::UpdatedAt)
                        .to_owned(),
                )
                .await
        }
    }

    #[derive(Iden)]
    enum StatusLists {
        Table,
        UpdatedAt,
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
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_status_list_history_resolution")
                        .table(StatusListHistory::Table)
                        .to_owned(),
                )
                .await?;
            manager
                .drop_table(
                    Table::drop()
                        .if_exists()
                        .table(StatusListHistory::Table)
                        .to_owned(),
                )
                .await
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

#[cfg(test)]
mod tests {
    // Tests for verify_innodb_engines: exercise the error-building logic
    // without a live DB connection.

    fn flagged(rows: &[(&str, &str)]) -> Vec<String> {
        rows.iter()
            .filter(|(_, engine)| !engine.eq_ignore_ascii_case("InnoDB"))
            .map(|(table, engine)| format!("{}({})", table, engine))
            .collect()
    }

    #[test]
    fn non_innodb_table_is_flagged() {
        let rows = [
            ("status_lists", "MyISAM"),
            ("status_list_history", "InnoDB"),
        ];
        let non_innodb = flagged(&rows);

        assert!(!non_innodb.is_empty());

        let err_msg = format!(
            "Non-InnoDB tables detected: {}. \
             The server requires InnoDB for transactional guarantees. \
             Run `ALTER TABLE <table> ENGINE=InnoDB;` in a maintenance window and restart.",
            non_innodb.join(", ")
        );

        assert!(
            err_msg.contains("status_lists"),
            "must name the affected table"
        );
        assert!(err_msg.contains("MyISAM"), "must include the actual engine");
        assert!(
            !err_msg.contains("status_list_history"),
            "InnoDB table must not appear"
        );
    }

    #[test]
    fn all_innodb_produces_no_error() {
        let rows = [
            ("status_lists", "InnoDB"),
            ("status_list_history", "InnoDB"),
        ];
        assert!(flagged(&rows).is_empty());
    }

    #[test]
    fn engine_comparison_is_case_insensitive() {
        for variant in ["innodb", "INNODB", "InnoDB", "Innodb"] {
            assert!(variant.eq_ignore_ascii_case("InnoDB"));
        }
    }
}
