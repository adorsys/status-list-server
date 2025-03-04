use axum::{http::Method, response::IntoResponse, routing::get, Router};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

async fn welcome() -> impl IntoResponse {
    "Status list Server"
}

#[tokio::main]
async fn main() {
    // cors Layer
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    let router = Router::new().route("/", get(welcome)).layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CatchPanicLayer::new())
            .layer(cors),
    );
    let listener = TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, router).await.unwrap()
}
