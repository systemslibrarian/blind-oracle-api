# Contributing

Thanks for your interest in the Blind Oracle API. This is a focused
demonstration project, so contributions that improve correctness, clarity,
security, or documentation are especially welcome.

## Development setup

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-oracle-api.git
cd crypto-lab-blind-oracle-api
cargo build
```

> **Note:** `tfhe` is built with the `x86_64-unix` feature, so the crate targets
> Linux/macOS on x86-64. On other platforms, build inside the provided Docker
> image or dev container. The first build compiles TFHE-rs and takes 5–10 minutes.

## Before opening a pull request

Run the same checks CI runs:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
```

The test suite generates real TFHE keys and performs genuine homomorphic
operations, so `cargo test` is slower than a typical Rust project — this is
expected.

## Design constraints

This server is a **blind oracle**. Any change must preserve these invariants:

1. The server never holds or derives a `ClientKey`.
2. The server never accesses plaintext (`plaintextAccessed` is always `false`).
3. Full ciphertexts and keys are never logged — only short, non-sensitive previews.

## Commit style

Use clear, conventional-style messages (`fix:`, `feat:`, `docs:`, `chore:`).
Keep changes small and reviewable.
