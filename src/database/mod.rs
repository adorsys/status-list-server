pub mod error;
pub mod queries;
pub mod repository;

pub use migrations::Migrator;

/// Database migrations module
pub mod migrations {
    use sea_orm_migration::prelude::*;

    /// Main migrator struct for database migrations
    pub struct Migrator;

    #[async_trait::async_trait]
    impl MigratorTrait for Migrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(tables::Migration)]
        }
    }

    /// Database tables module containing table creation migrations
    pub mod tables {
        use super::*;

        /// Migration struct for creating database tables
        #[derive(DeriveMigrationName)]
        pub struct Migration;

        #[async_trait::async_trait]
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
                            .col(ColumnDef::new(Credentials::PublicKey).text().not_null())
                            .col(ColumnDef::new(Credentials::Alg).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                // Create StatusListTokens table for storing status list tokens
                manager
                    .create_table(
                        Table::create()
                            .table(StatusListTokens::Table)
                            .if_not_exists()
                            .col(
                                ColumnDef::new(StatusListTokens::ListId)
                                    .string()
                                    .not_null()
                                    .primary_key(),
                            )
                            .col(ColumnDef::new(StatusListTokens::Exp).big_integer())
                            .col(ColumnDef::new(StatusListTokens::Issuer).string().not_null())
                            .col(
                                ColumnDef::new(StatusListTokens::Iat)
                                    .big_integer()
                                    .not_null(),
                            )
                            .col(
                                ColumnDef::new(StatusListTokens::StatusList)
                                    .json()
                                    .not_null(),
                            )
                            .col(ColumnDef::new(StatusListTokens::Sub).string().not_null())
                            .col(ColumnDef::new(StatusListTokens::Ttl).big_integer())
                            .foreign_key(
                                // Foreign key use to ensures that the Issuer in the StatusListTokens table references a valid Issuer in the Credentials table
                                ForeignKey::create()
                                    .name("fk_issuer")
                                    .from(StatusListTokens::Table, StatusListTokens::Issuer)
                                    .to(Credentials::Table, Credentials::Issuer),
                            )
                            .to_owned(),
                    )
                    .await?;

                Ok(())
            }

            /// Drops the database tables
            async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
                // Drop tables in reverse order to handle foreign key constraints
                manager
                    .drop_table(Table::drop().table(Credentials::Table).to_owned())
                    .await?;
                manager
                    .drop_table(Table::drop().table(StatusListTokens::Table).to_owned())
                    .await?;
                Ok(())
            }
        }

        #[derive(Iden)]
        enum Credentials {
            Table,
            Issuer,
            PublicKey,
            Alg,
        }

        #[derive(Iden)]
        enum StatusListTokens {
            Table,
            Issuer,
            ListId,
            Exp,
            Iat,
            StatusList,
            Sub,
            Ttl,
        }
    }
}
