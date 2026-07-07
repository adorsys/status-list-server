pub(crate) mod error;
pub(crate) mod queries;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr};

pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS credentials (
            issuer TEXT PRIMARY KEY,
            public_key JSON NOT NULL
        )
        "#,
    )
    .await?;

    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS status_lists (
            list_id TEXT PRIMARY KEY,
            issuer TEXT NOT NULL,
            status_list JSON NOT NULL,
            sub TEXT NOT NULL,
            CONSTRAINT fk_status_lists_issuer
                FOREIGN KEY (issuer)
                REFERENCES credentials (issuer)
                ON DELETE CASCADE
                ON UPDATE CASCADE
        )
        "#,
    )
    .await?;

    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_status_lists_list_id ON status_lists (list_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_status_lists_issuer ON status_lists (issuer)",
    )
    .await?;
    db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_status_lists_sub ON status_lists (sub)")
        .await?;

    Ok(())
}
