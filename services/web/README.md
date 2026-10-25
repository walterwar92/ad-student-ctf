# SecureNotes (service: `web`)

A minimal private-notes web app with a JSON API. Every user keeps their own
notes; notes are private to the account that created them.

- **Default port:** `5001`
- **Transport:** HTTP, JSON request/response bodies
- **Auth:** bearer token returned at register/login, sent as
  `Authorization: Bearer <token>`

## Endpoints

### `POST /api/register`
Create a new account.

Request:
```json
{"username": "alice", "password": "s3cret"}
```
Responses:
- `201 {"token": "<token>"}` on success
- `409 {"error": "..."}` if the username is already taken
- `400 {"error": "..."}` if the body is missing fields

### `POST /api/login`
Log in to an existing account.

Request:
```json
{"username": "alice", "password": "s3cret"}
```
Responses:
- `200 {"token": "<token>"}` on success
- `401 {"error": "..."}` on bad credentials

### `POST /api/notes`  (auth required)
Create a note for the current user.

Headers: `Authorization: Bearer <token>`

Request:
```json
{"title": "shopping", "body": "milk, eggs"}
```
Response:
- `201 {"id": 42}`

### `GET /api/notes`  (auth required)
List the current user's notes.

Response:
```json
{"notes": [{"id": 42, "title": "shopping", "body": "milk, eggs"}]}
```

### `GET /api/notes/search?q=<term>`  (auth required)
Search the current user's notes. Matches notes whose title or body contains
the term `q`.

Response:
```json
{"notes": [{"id": 42, "title": "shopping", "body": "milk, eggs"}]}
```

## Running locally

```bash
pip install -r requirements.txt
PORT=5001 python app.py
```

Data is stored in `./data/web.db` (SQLite), created automatically on startup.
