# blind-oracle-api

## What It Is

Blind Oracle API is a Rust back-end that performs fully homomorphic encrypted addition on `FheUint8` ciphertexts using [TFHE-rs](https://github.com/zama-ai/tfhe-rs). The server receives a `ServerKey` (evaluation key) and two encrypted 8-bit integers from the browser client, computes their homomorphic sum via gate bootstrapping, and returns the encrypted result — without ever accessing plaintext. TFHE is a lattice-based FHE scheme with post-quantum security assumptions; the `ClientKey` never leaves the browser, making the server a blind oracle that processes ciphertexts it cannot decrypt.

## When to Use It

- **Privacy-preserving server-side computation** — when a client needs a server to compute on its data without revealing the inputs or outputs.
- **Demonstrating FHE gate bootstrapping** — each `FheUint8` operation resets the noise budget automatically, enabling unlimited computation depth with no manual noise management.
- **Blind oracle pattern** — when the trust model requires the server to hold only an evaluation key and never possess decryption capability.
- **Post-quantum secure computation** — TFHE's lattice-based hardness assumption is believed to resist quantum attacks, unlike RSA or ECC.
- **Not suitable for high-throughput or low-latency workloads** — a single `FheUint8` addition takes 100 ms–2 s; use conventional encryption or MPC when sub-millisecond latency is required.

## Live Demo

This API is the back-end for the Blind Oracle experiment at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/). The browser generates a TFHE key pair, encrypts two 8-bit integers, sends the ciphertexts and `ServerKey` to this API, and decrypts the homomorphic sum locally. The user can enter any two numbers (0–255) and verify that the server returns the correct encrypted result without ever seeing plaintext.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-oracle-api.git
cd crypto-lab-blind-oracle-api
cargo build --release
cargo run --release
```

The server listens on port `3001` by default. Set the `PORT` environment variable to override:

```bash
PORT=8080 cargo run --release
```

> **Note:** TFHE-rs is a large cryptographic library. First build takes 5–10 minutes; subsequent builds are incremental.

## Part of the Crypto-Lab Suite

This API is one component of the [Crypto-Lab](https://systemslibrarian.github.io/crypto-lab/) suite of cryptographic demonstrations.

---

> *Whether you eat or drink or whatever you do, do it all for the glory of God.* — 1 Corinthians 10:31
