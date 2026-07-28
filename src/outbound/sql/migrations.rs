//! Database migrations for the SeaORM adapter.

use sea_orm_migration::prelude::*;

pub struct Migrator;

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
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

fn pin_innodb_on_mysql(manager: &SchemaManager<'_>, stmt: &mut TableCreateStatement) {
    if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        stmt.engine("InnoDB");
    }
}
