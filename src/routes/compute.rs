use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheUint8, ServerKey};

/// Cache entry: deserialized ServerKey + insertion time.
struct CachedKey {
    key: Arc<ServerKey>,
    inserted_at: Instant,
}

/// Shared application state with server key cache.
pub struct AppState {
    /// Cache keyed by the first 32 chars of the base64 server key.
    /// Entries expire after 10 minutes.
    cache: Mutex<HashMap<String, CachedKey>>,
}

const CACHE_TTL_SECS: u64 = 600; // 10 minutes

impl AppState {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get or deserialize a ServerKey. Returns an Arc so it can be cloned cheaply
    /// for `set_server_key` (which takes ownership).
    fn get_or_insert_key(&self, key_b64: &str, key_bytes: &[u8]) -> Result<Arc<ServerKey>, String> {
        let cache_key = &key_b64[..std::cmp::min(32, key_b64.len())];
        let mut cache = self.cache.lock().map_err(|_| "Cache lock poisoned")?;

        // Evict expired entries
        cache.retain(|_, v| v.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS);

        if let Some(entry) = cache.get(cache_key) {
            if entry.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Arc::clone(&entry.key));
            }
        }

        // Deserialize (expensive: 1-5s)
        let sk: ServerKey =
            bincode::deserialize(key_bytes).map_err(|e| format!("ServerKey deserialize: {e}"))?;
        let arc_sk = Arc::new(sk);
        cache.insert(
            cache_key.to_string(),
            CachedKey {
                key: Arc::clone(&arc_sk),
                inserted_at: Instant::now(),
            },
        );
        Ok(arc_sk)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeRequest {
    server_key: String,
    ct_a: String,
    ct_b: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeResponse {
    ct_result: String,
    operation: String,
    plaintext_accessed: bool,
    scheme: String,
    bootstrapping: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    error: String,
    plaintext_accessed: bool,
}

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
            plaintext_accessed: false,
        }),
    )
}

/// Log only the first 12 characters of a base64 ciphertext — never full payloads.
fn preview(b64: &str) -> &str {
    &b64[..std::cmp::min(12, b64.len())]
}

/// POST /compute/add
///
/// Receives two base64-encoded FheUint8 ciphertexts and a base64-encoded ServerKey.
/// Performs gate-bootstrapped homomorphic addition and returns the encrypted result.
///
/// The server never holds a ClientKey and cannot decrypt any ciphertext.
///
/// Performance notes:
/// - ServerKey deserialization: 1–5 seconds (cached after first use per client session)
/// - FheUint8 addition with gate bootstrapping: 100ms–2s depending on hardware
/// - FheUint8 range: 0–255, addition wraps modulo 256 on overflow
pub async fn compute_add(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ComputeRequest>,
) -> Result<Json<ComputeResponse>, (StatusCode, Json<ErrorResponse>)> {
    println!(
        "[COMPUTE] Received add request. ctA: {}… ctB: {}…",
        preview(&payload.ct_a),
        preview(&payload.ct_b)
    );

    // Decode server key
    let sk_bytes = BASE64
        .decode(&payload.server_key)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid encoding"))?;

    // Decode ciphertexts
    let ct_a_bytes = BASE64
        .decode(&payload.ct_a)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid encoding"))?;
    let ct_b_bytes = BASE64
        .decode(&payload.ct_b)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid encoding"))?;

    // Get or cache the server key
    let server_key = state
        .get_or_insert_key(&payload.server_key, &sk_bytes)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid ciphertext format"))?;

    // FHE operations are CPU-bound — run in blocking thread pool.
    // set_server_key is thread-local, so we must call it on the same thread
    // that performs the computation.
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        // Clone the server key (set_server_key takes ownership).
        // This is cheaper than deserialization.
        let sk_owned: ServerKey = (*server_key).clone();
        set_server_key(sk_owned);

        let ct_a: FheUint8 = bincode::deserialize(&ct_a_bytes)
            .map_err(|e| format!("ctA deserialize: {e}"))?;
        let ct_b: FheUint8 = bincode::deserialize(&ct_b_bytes)
            .map_err(|e| format!("ctB deserialize: {e}"))?;

        // Gate-bootstrapped homomorphic addition.
        // TFHE-rs automatically performs bootstrapping on every operation,
        // resetting noise and enabling unlimited circuit depth.
        let ct_result = &ct_a + &ct_b;

        let result_bytes = bincode::serialize(&ct_result)
            .map_err(|e| format!("Result serialize: {e}"))?;
        Ok(result_bytes)
    })
    .await
    .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Computation failed"))?
    .map_err(|e| {
        eprintln!("[COMPUTE] Error: {e}");
        error_response(StatusCode::BAD_REQUEST, "Invalid ciphertext format")
    })?;

    let ct_result_b64 = BASE64.encode(&result);

    println!(
        "[COMPUTE] Add complete. result: {}… plaintextAccessed: false",
        preview(&ct_result_b64)
    );

    Ok(Json(ComputeResponse {
        ct_result: ct_result_b64,
        operation: "tfhe_fhe_add".to_string(),
        plaintext_accessed: false,
        scheme: "TFHE-rs".to_string(),
        bootstrapping: "gate_bootstrapping_per_operation".to_string(),
    }))
}
