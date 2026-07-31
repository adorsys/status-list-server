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
        ]
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
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_status_list_history_exp")
                        .table(StatusListHistory::Table)
                        .to_owned(),
                )
                .await
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

/// Pins InnoDB on MySQL so `update_with_snapshot`'s UPDATE+INSERT roll back as a
/// unit rather than depending on the server's default engine. MySQL-only:
/// sea-query renders the engine option as a literal `ENGINE=InnoDB` clause on
/// every backend, which SQLite and Postgres reject with a syntax error.
fn pin_innodb_on_mysql(manager: &SchemaManager<'_>, stmt: &mut TableCreateStatement) {
    if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        stmt.engine("InnoDB");
    }
}
