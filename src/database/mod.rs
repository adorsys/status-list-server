pub(crate) mod error;
pub(crate) mod queries;

pub(crate) use migrations::Migrator;

/// Database migrations module
pub(crate) mod migrations {
    use sea_orm_migration::prelude::*;

    /// Main migrator struct for database migrations
    pub(crate) struct Migrator;

    #[async_trait::async_trait]
    impl MigratorTrait for Migrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![
                Box::new(tables::Migration),
                Box::new(add_updated_at::Migration),
            ]
        }
    }

    /// Database tables module containing table creation migrations
    pub(crate) mod tables {
        use super::*;

        /// Migration struct for creating database tables
        #[derive(DeriveMigrationName)]
        pub(crate) struct Migration;

        #[async_trait::async_trait]
        #[allow(elided_lifetimes_in_paths)]
        impl MigrationTrait for Migration {
            /// Creates the necessary database tables if they don't exist
            async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
                // Create Credentials table for storing issuer credentials
                manager
                    .create_table(
                        Table::create()
                            .table(Credentials::Table)
                            .if_not_exists()
                            .col(
                                ColumnDef::new(Credentials::Issuer)
                                    .string()
                                    .not_null()
                                    .primary_key(),
                            )
                            .col(ColumnDef::new(Credentials::PublicKey).json().not_null())
                            .to_owned(),
                    )
                    .await?;

                // Create StatusLists table for storing status list entries
                manager
                    .create_table(
                        Table::create()
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
                                // Foreign key use to ensures that the Issuer in the StatusLists table references
                                // a valid Issuer in the Credentials table
                                ForeignKey::create()
                                    .name("fk_status_lists_issuer")
                                    .from(StatusLists::Table, StatusLists::Issuer)
                                    .to(Credentials::Table, Credentials::Issuer)
                                    .on_delete(ForeignKeyAction::Cascade)
                                    .on_update(ForeignKeyAction::Cascade),
                            )
                            .to_owned(),
                    )
                    .await?;

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
        #[derive(DeriveMigrationName)]
        pub(crate) struct Migration;

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
                    .await
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
}
