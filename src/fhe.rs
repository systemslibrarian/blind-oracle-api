/// FHE context for TFHE-rs.
///
/// The server does NOT generate keys. It receives the ServerKey from the client
/// on each compute request (or retrieves it from cache). It calls
/// `set_server_key(server_key)` to register it for the current thread before
/// performing any FHE operations.
///
/// TFHE-rs doesn't require server-side initialization beyond registering the
/// server key per request. This context confirms the library is available.

pub struct FheContext {
    pub ready: bool,
}

pub fn init() -> FheContext {
    println!("[FHE] TFHE-rs native bindings ready.");
    println!("[FHE] Scheme: TFHE with gate bootstrapping.");
    println!("[FHE] ServerKey: received per-request from client.");
    println!("[FHE] ClientKey: never held by this server.");
    FheContext { ready: true }
}
