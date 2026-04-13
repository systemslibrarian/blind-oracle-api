mod fhe;
mod routes;

use axum::{routing::{get, post}, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use axum::extract::DefaultBodyLimit;
use tower_http::cors::CorsLayer;
use axum::http::{header, HeaderValue, Method};

use routes::compute::{compute_add, AppState};

#[tokio::main]
async fn main() {
    // Initialize FHE context (confirms TFHE-rs is available)
    let ctx = fhe::init();
    if !ctx.ready {
        eprintln!("[FHE] Failed to initialize TFHE-rs context.");
        std::process::exit(1);
    }

    let state = Arc::new(AppState::new());

    let cors = CorsLayer::new()
        .allow_origin([
            "https://systemslibrarian.github.io".parse::<HeaderValue>().unwrap(),
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/compute/add", post(compute_add))
        .layer(cors)
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100MB for FHE server key + ciphertexts
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("[SERVER] Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "blind-oracle-api",
        "status": "ok",
        "routes": {
            "health": "/health",
            "computeAdd": "/compute/add"
        },
        "methods": {
            "health": "GET",
            "computeAdd": "POST"
        }
    }))
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "scheme": "TFHE-rs",
        "fhe": true,
        "bootstrapping": "gate_bootstrapping_per_operation",
        "expectedComputeMs": "100-2000",
        "serverKeyDeserializeMs": "1000-5000 (cached after first use)"
    }))
}
