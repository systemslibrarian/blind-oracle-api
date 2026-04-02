# blind-oracle-api

Blind Oracle API performs fully homomorphic encrypted addition on `FheUint8` values using TFHE-rs (native Rust).
The server holds only a `ServerKey` (evaluation key) received from the client. It cannot decrypt any ciphertext.
The `ClientKey` never leaves the browser.

## True FHE via Gate Bootstrapping

This server uses TFHE-rs compiled natively in Rust. Every `FheUint8` addition
performs gate bootstrapping automatically — the noise budget resets with each
operation, enabling unlimited computation depth. This is Fully Homomorphic
Encryption. The server holds only a `ServerKey` (evaluation key) derived from
the client's key pair. It cannot decrypt its own output under any circumstances.

## Endpoints

### GET /health
Returns service readiness and FHE scheme details.

Example response:

```json
{
  "status": "ok",
  "scheme": "TFHE-rs",
  "fhe": true,
  "bootstrapping": "gate_bootstrapping_per_operation",
  "expectedComputeMs": "100-2000",
  "serverKeyDeserializeMs": "1000-5000 (cached after first use)"
}
```

### POST /compute/add
Accepts two base64-encoded `FheUint8` ciphertexts and a base64-encoded `ServerKey`.
Returns the homomorphic sum as a base64-encoded ciphertext.

Request body:

```json
{
  "serverKey": "<base64 encoded bincode-serialized ServerKey>",
  "ctA": "<base64 encoded bincode-serialized FheUint8>",
  "ctB": "<base64 encoded bincode-serialized FheUint8>"
}
```

Response body:

```json
{
  "ctResult": "<base64 encoded bincode-serialized FheUint8>",
  "operation": "tfhe_fhe_add",
  "plaintextAccessed": false,
  "scheme": "TFHE-rs",
  "bootstrapping": "gate_bootstrapping_per_operation"
}
```

## Build Time

TFHE-rs is a large cryptographic library. First build takes 5–10 minutes.
Subsequent builds are incremental. Render's build logs will show compilation
progress.

## Render Deploy

This repository includes [render.yaml](render.yaml) for one-click infrastructure configuration.

1. Connect the repository to Render as a Web Service.
2. Render uses the included `Dockerfile` to build the Rust binary.
3. TFHE-rs compile time is long (~5–10 minutes on first build). This is normal.
4. Free tier sleeps after about 15 minutes of inactivity, so cold starts can take around 30 seconds.

If Render's free/starter tier is too slow for FHE computation, upgrading to a
higher-tier instance with more CPU cores will improve performance significantly.

## Security Notes

The API process stores only a `ServerKey` (evaluation key) needed for homomorphic computation.
It does not generate or store client-side decryption material (`ClientKey`).
`plaintextAccessed: false` is included on every response, including errors.
Request logging is restricted to 12-character ciphertext previews and never logs full payloads.
CORS is restricted to `https://systemslibrarian.github.io` and `http://localhost:5173`.

## Stack

| Component | Technology | Deployment |
| --------- | --------------------------------- | ---------- |
| Backend   | Rust + Axum + TFHE-rs (native)    | Render     |

## Credits

- [TFHE-rs by Zama AI](https://github.com/zama-ai/tfhe-rs) (native Rust FHE library)
- [Axum](https://github.com/tokio-rs/axum) (Rust web framework)
