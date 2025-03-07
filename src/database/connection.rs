use std::env;

use sqlx::{postgres::PgPoolOptions, Executor, PgPool};

/// establish database connection with migrations  
#[allow(unused)]
pub async fn establish_connection() -> PgPool {
    let url = env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let pool = PgPoolOptions::new().connect(&url).await.unwrap();

    run_migration(&pool).await;
    pool
}

#[allow(unused)]
async fn run_migration(pool: &PgPool) {
    pool.execute(include_str!("./migrations/001_status_list.sql"))
        .await
        .expect("Failed to initialize DB");
}
