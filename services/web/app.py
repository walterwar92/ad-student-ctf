import os
import sqlite3
import secrets
import threading

from flask import Flask, request, jsonify

DEFAULT_PORT = 5001

# cwd-relative by default so each working directory (per-team in native mode,
# per-container in Docker) gets its own isolated database.
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(os.getcwd(), "data")
DB_PATH = os.path.join(DATA_DIR, "web.db")

app = Flask(__name__)
# Cap request body size: without this a single oversized POST is buffered into
# RAM and can OOM the process -> the vulnbox supervisor then takes the WHOLE box
# (web+crypto+depot) down. The checker only ever sends sub-kilobyte bodies.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

os.makedirs(DATA_DIR, exist_ok=True)

_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_db_lock = threading.Lock()

with _db_lock:
    _conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)"
    )
    _conn.execute(
        "CREATE TABLE IF NOT EXISTS notes ("
        "id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)"
    )
    _conn.commit()

# bearer token -> user_id
_tokens = {}
_tokens_lock = threading.Lock()


def _issue_token(user_id):
    token = secrets.token_hex(24)
    with _tokens_lock:
        _tokens[token] = user_id
    return token


def _current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    with _tokens_lock:
        return _tokens.get(token)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) \
            or not username or not password:
        return jsonify({"error": "username and password required"}), 400
    with _db_lock:
        row = _conn.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        if row is not None:
            return jsonify({"error": "username already taken"}), 409
        cur = _conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password),
        )
        _conn.commit()
        uid = cur.lastrowid
    return jsonify({"token": _issue_token(uid)}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "username and password required"}), 400
    with _db_lock:
        row = _conn.execute(
            "SELECT id, password FROM users WHERE username=?", (username,)
        ).fetchone()
    if row is None or row["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": _issue_token(row["id"])}), 200


@app.route("/api/notes", methods=["POST"])
def create_note():
    uid = _current_user()
    if uid is None:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    title = data.get("title")
    body = data.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify({"error": "title and body required"}), 400
    with _db_lock:
        cur = _conn.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (uid, title, body),
        )
        _conn.commit()
        nid = cur.lastrowid
    return jsonify({"id": nid}), 201


@app.route("/api/notes", methods=["GET"])
def list_notes():
    uid = _current_user()
    if uid is None:
        return jsonify({"error": "unauthorized"}), 401
    with _db_lock:
        rows = _conn.execute(
            "SELECT id, title, body FROM notes WHERE user_id=? ORDER BY id",
            (uid,),
        ).fetchall()
    notes = [{"id": r["id"], "title": r["title"], "body": r["body"]} for r in rows]
    return jsonify({"notes": notes}), 200


@app.route("/api/notes/search", methods=["GET"])
def search_notes():
    uid = _current_user()
    if uid is None:
        return jsonify({"error": "unauthorized"}), 401
    q = request.args.get("q", "")
    # Parameterized query: q is bound as data, never parsed as SQL. The server
    # adds the wildcards, so benign substring search is unchanged, while the
    # UNION/comment payload becomes a harmless literal -> SQLi closed.
    like = "%" + q + "%"
    sql = "SELECT id,title,body FROM notes WHERE user_id=? AND (title LIKE ? OR body LIKE ?)"
    try:
        with _db_lock:
            rows = _conn.execute(sql, (uid, like, like)).fetchall()
    except sqlite3.Error:
        return jsonify({"error": "bad query"}), 400
    notes = [{"id": r["id"], "title": r["title"], "body": r["body"]} for r in rows]
    return jsonify({"notes": notes}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    app.run(host="0.0.0.0", port=port, threaded=True)
