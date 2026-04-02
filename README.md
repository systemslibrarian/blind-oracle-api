# blind-oracle-api

Blind Oracle API performs homomorphic addition on encrypted integers using Microsoft SEAL through node-seal.
The service initializes BFV evaluation context at startup and exposes a single compute endpoint.
It does not hold any client private material and cannot recover plaintext values from ciphertext payloads.

## Endpoints

### GET /health
Returns service and SEAL readiness state.

Example response:

```json
{
  "status": "ok",
  "seal": "ready"
}
```

### POST /compute/add
Accepts two ciphertext strings and returns a ciphertext sum.

Request body:

```json
{
  "ctA": "<base64 ciphertext>",
  "ctB": "<base64 ciphertext>"
}
```

Response body:

```json
{
  "ctResult": "<base64 ciphertext>",
  "operation": "homomorphic_add",
  "plaintextAccessed": false,
  "serverKeyType": "evaluation_only"
}
```

## Render Deploy

This repository includes [render.yaml](render.yaml) for one-click infrastructure configuration.

1. Connect the repository to Render as a Web Service.
2. Render uses `npm install` to build and `node index.js` to start.
3. Free tier sleeps after about 15 minutes of inactivity, so cold starts can take around 30 seconds.

## Security Notes

The API process stores only evaluation primitives needed for homomorphic add.
It does not generate or store client-side decryption material.
Request logging is restricted to short ciphertext previews and never logs full payloads.
CORS is restricted to `https://systemslibrarian.github.io`.
