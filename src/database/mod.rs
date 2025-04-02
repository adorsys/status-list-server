pub mod error;
pub mod queries;
pub mod repository;

pub use migrations::Migrator;

pub mod migrations {
    use sea_orm_migration::prelude::*;

    pub struct Migrator;

    #[async_trait::async_trait]
    impl MigratorTrait for Migrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(m20230329_000001_create_tables::Migration)]
        }
    }

    pub mod m20230329_000001_create_tables {
        use super::*;

        #[derive(DeriveMigrationName)]
        pub struct Migration;

        #[async_trait::async_trait]
        impl MigrationTrait for Migration {
            async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                            .col(ColumnDef::new(Credentials::PublicKey).text().not_null()) // Changed to text
                            .col(ColumnDef::new(Credentials::Alg).string().not_null())
                            .to_owned(),
                    )
                    .await?;

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
                            .col(ColumnDef::new(StatusListTokens::Exp).integer())
                            .col(ColumnDef::new(StatusListTokens::Iat).integer().not_null())
                            .col(
                                ColumnDef::new(StatusListTokens::StatusList)
                                    .json()
                                    .not_null(),
                            )
                            .col(ColumnDef::new(StatusListTokens::Sub).string().not_null())
                            .col(ColumnDef::new(StatusListTokens::Ttl).string())
                            .to_owned(),
                    )
                    .await?;

                Ok(())
            }

            async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            ListId,
            Exp,
            Iat,
            StatusList,
            Sub,
            Ttl,
        }
    }
}
