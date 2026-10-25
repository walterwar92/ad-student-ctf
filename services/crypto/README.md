# CipherVault (`crypto`)

A small vault service that stores user secrets **encrypted at rest** with AES.
Each secret gets an item `id` and a private `token` that acts as the owner's
claim secret. Only someone who knows the `token` can reveal the plaintext.

- Default port: **5002**
- Transport: HTTP, JSON bodies and responses.

## Endpoints

### `POST /api/store`
Store a new secret.

Request:
```json
{"owner": "alice", "secret": "my confidential note"}
```
Response `201`:
```json
{"id": "a1b2c3d4", "token": "0123...<32 hex chars>"}
```
The service encrypts `secret` (UTF-8) and keeps only the ciphertext in memory.
Keep the `token` — you need it to read the secret back.

### `GET /api/item/<id>`
Public metadata for an item.

Response `200`:
```json
{"id": "a1b2c3d4", "owner": "alice", "ciphertext": "<hex>", "length": 20}
```
`404` if the id does not exist.

### `GET /api/items`
Public enumeration of all stored items.

Response `200`:
```json
{"items": [{"id": "a1b2c3d4", "owner": "alice"}, ...]}
```

### `POST /api/reveal`
Decrypt and return the plaintext — requires the matching `token`.

Request:
```json
{"id": "a1b2c3d4", "token": "0123...<32 hex chars>"}
```
Response `200`:
```json
{"secret": "my confidential note"}
```
`403` if the token is wrong, `404` if the id is unknown.

## Running

```bash
pip install -r requirements.txt
PORT=5002 python app.py
```
