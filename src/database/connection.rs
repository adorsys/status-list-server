use std::env;

use sqlx::{postgres::{PgConnectOptions, PgPoolOptions}, Executor, PgPool};

pub async fn establish_connection() -> PgPool {
    let url = env::var("DATABASE_URL").expect("DATABASE_URL env not set");
    let pool = PgPoolOptions::new().max_connections(5).connect(&url).await.unwrap();
    run_migration(&pool).await;
    pool
}

async fn run_migration(pool: &PgPool) {
    pool.execute(include_str!("./migrations/status_list.sql"))
    	.await
    	.expect("Failed to initialize DB");
}