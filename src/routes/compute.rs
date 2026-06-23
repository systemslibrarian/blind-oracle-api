use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[allow(unused_imports)]
use tfhe::prelude::*;
use tfhe::{set_server_key, CompressedServerKey, FheUint8, ServerKey};

/// Cache entry: deserialized ServerKey + insertion time.
struct CachedKey {
    key: Arc<ServerKey>,
    inserted_at: Instant,
}

/// Shared application state with server key cache.
pub struct AppState {
    /// Cache keyed by a hash of the full base64 server key.
    /// Entries expire after [`CACHE_TTL_SECS`].
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
    ///
    /// Deserializing + decompressing a TFHE server key is expensive (1-5s), so
    /// results are cached per unique key for [`CACHE_TTL_SECS`]. The cache is
    /// keyed by a hash of the *full* base64 string (not a prefix) to avoid
    /// collisions between keys that share a common prefix.
    fn get_or_insert_key(&self, key_b64: &str, key_bytes: &[u8]) -> Result<Arc<ServerKey>, String> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key_b64.hash(&mut hasher);
        let cache_key = hasher.finish().to_string();
        let mut cache = self.cache.lock().map_err(|_| "Cache lock poisoned")?;

        // Evict expired entries.
        cache.retain(|_, v| v.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS);

        if let Some(entry) = cache.get(&cache_key) {
            if entry.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Arc::clone(&entry.key));
            }
        }

        // Deserialize compressed key (expensive) and decompress.
        let compressed_sk: CompressedServerKey =
            bincode::deserialize(key_bytes).map_err(|e| format!("ServerKey deserialize: {e}"))?;
        let sk: ServerKey = compressed_sk.decompress();
        let arc_sk = Arc::new(sk);
        cache.insert(
            cache_key,
            CachedKey {
                key: Arc::clone(&arc_sk),
                inserted_at: Instant::now(),
            },
        );
        Ok(arc_sk)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
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

/// Return only the first 12 characters of a base64 payload for logging —
/// never log full ciphertexts or keys.
fn preview(b64: &str) -> &str {
    &b64[..std::cmp::min(12, b64.len())]
}

/// Core FHE computation: deserialize two `FheUint8` ciphertexts, add them with
/// gate bootstrapping, and serialize the encrypted result.
///
/// The caller MUST have registered a server key on the current thread via
/// `set_server_key` before invoking this (the key is thread-local in TFHE-rs).
///
/// This function is intentionally free of HTTP/async concerns so it can be unit
/// tested directly against real TFHE keys.
fn fhe_add(ct_a_bytes: &[u8], ct_b_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let ct_a: FheUint8 =
        bincode::deserialize(ct_a_bytes).map_err(|e| format!("ctA deserialize: {e}"))?;
    let ct_b: FheUint8 =
        bincode::deserialize(ct_b_bytes).map_err(|e| format!("ctB deserialize: {e}"))?;

    // Gate-bootstrapped homomorphic addition. TFHE-rs bootstraps on every
    // operation, resetting noise and enabling unlimited circuit depth.
    // FheUint8 wraps modulo 256 on overflow.
    let ct_result = &ct_a + &ct_b;

    bincode::serialize(&ct_result).map_err(|e| format!("Result serialize: {e}"))
}

/// POST /compute/add
///
/// Receives two base64-encoded `FheUint8` ciphertexts and a base64-encoded
/// compressed `ServerKey`. Performs gate-bootstrapped homomorphic addition and
/// returns the encrypted result.
///
/// The server never holds a `ClientKey` and cannot decrypt any ciphertext.
///
/// Performance notes:
/// - ServerKey deserialization: 1-5 seconds (cached after first use per key).
/// - FheUint8 addition with gate bootstrapping: 100ms-2s depending on hardware.
/// - FheUint8 range: 0-255; addition wraps modulo 256 on overflow.
#[tracing::instrument(skip_all)]
pub async fn compute_add(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ComputeRequest>,
) -> Result<Json<ComputeResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::info!(
        ct_a = %preview(&payload.ct_a),
        ct_b = %preview(&payload.ct_b),
        "received add request"
    );

    let sk_bytes = BASE64
        .decode(&payload.server_key)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in serverKey"))?;
    let ct_a_bytes = BASE64
        .decode(&payload.ct_a)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in ctA"))?;
    let ct_b_bytes = BASE64
        .decode(&payload.ct_b)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in ctB"))?;

    // Get or cache the (expensive to deserialize) server key.
    let server_key = state
        .get_or_insert_key(&payload.server_key, &sk_bytes)
        .map_err(|e| {
            tracing::warn!(error = %e, "server key rejected");
            error_response(StatusCode::BAD_REQUEST, "Invalid server key")
        })?;

    // FHE operations are CPU-bound — run on the blocking pool. `set_server_key`
    // is thread-local, so it must be called on the same thread that computes.
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        // Clone the cached key (set_server_key takes ownership). This is far
        // cheaper than re-deserializing.
        let sk_owned: ServerKey = (*server_key).clone();
        set_server_key(sk_owned);
        fhe_add(&ct_a_bytes, &ct_b_bytes)
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "compute task panicked or was cancelled");
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Computation failed")
    })?
    .map_err(|e| {
        tracing::warn!(error = %e, "ciphertext rejected");
        error_response(StatusCode::BAD_REQUEST, "Invalid ciphertext")
    })?;

    let ct_result_b64 = BASE64.encode(&result);
    tracing::info!(
        result = %preview(&ct_result_b64),
        plaintext_accessed = false,
        "add complete"
    );

    Ok(Json(ComputeResponse {
        ct_result: ct_result_b64,
        operation: "tfhe_fhe_add".to_string(),
        plaintext_accessed: false,
        scheme: "TFHE-rs".to_string(),
        bootstrapping: "gate_bootstrapping_per_operation".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::prelude::*; // FheEncrypt / FheDecrypt trait methods
    use tfhe::{generate_keys, ClientKey, ConfigBuilder};

    /// Generate a fresh (ClientKey, decompressed ServerKey) pair for testing.
    fn test_keys() -> (ClientKey, ServerKey) {
        let config = ConfigBuilder::default().build();
        generate_keys(config)
    }

    /// Serialize an encrypted u8 the way the browser client would.
    fn encrypt_bytes(value: u8, ck: &ClientKey) -> Vec<u8> {
        let ct = FheUint8::encrypt(value, ck);
        bincode::serialize(&ct).unwrap()
    }

    #[test]
    fn preview_truncates_and_is_safe_on_short_input() {
        assert_eq!(preview("abcdefghijklmnop"), "abcdefghijkl");
        assert_eq!(preview("short"), "short");
        assert_eq!(preview(""), "");
    }

    #[test]
    fn fhe_add_matches_plaintext_addition() {
        let (ck, sk) = test_keys();
        set_server_key(sk);

        let (a, b) = (7u8, 200u8);
        let result = fhe_add(&encrypt_bytes(a, &ck), &encrypt_bytes(b, &ck)).unwrap();

        let ct: FheUint8 = bincode::deserialize(&result).unwrap();
        let got: u8 = ct.decrypt(&ck);
        assert_eq!(got, a.wrapping_add(b)); // 207
    }

    #[test]
    fn fhe_add_wraps_modulo_256_on_overflow() {
        let (ck, sk) = test_keys();
        set_server_key(sk);

        let (a, b) = (200u8, 100u8);
        let result = fhe_add(&encrypt_bytes(a, &ck), &encrypt_bytes(b, &ck)).unwrap();

        let ct: FheUint8 = bincode::deserialize(&result).unwrap();
        let got: u8 = ct.decrypt(&ck);
        assert_eq!(got, a.wrapping_add(b)); // 44
    }

    #[test]
    fn fhe_add_rejects_garbage_ciphertext() {
        let (ck, sk) = test_keys();
        set_server_key(sk);
        let valid = encrypt_bytes(1, &ck);
        assert!(fhe_add(&valid, b"not a ciphertext").is_err());
    }

    #[test]
    fn cache_returns_same_arc_on_hit() {
        let (ck, _sk) = test_keys();
        let compressed = CompressedServerKey::new(&ck);
        let bytes = bincode::serialize(&compressed).unwrap();

        let state = AppState::new();
        let first = state.get_or_insert_key("client-1", &bytes).unwrap();
        let second = state.get_or_insert_key("client-1", &bytes).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "second call should hit cache");
    }

    #[test]
    fn cache_rejects_invalid_server_key() {
        let state = AppState::new();
        assert!(state.get_or_insert_key("bad", b"not a server key").is_err());
    }
}
