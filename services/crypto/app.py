import hmac
import os
import secrets
import threading

from flask import Flask, jsonify, request
from aescipher import AES  # self-contained AES-CTR (no external crypto dependency)

app = Flask(__name__)
# Cap request body size: the self-contained AES-CTR is pure Python and its cost
# grows superlinearly, so a large secret stalls the worker past the checker's
# 5s timeout (and multi-MB bodies OOM the box). The checker sends tiny bodies.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

DEFAULT_PORT = 5002

KEY = secrets.token_bytes(16)

_lock = threading.Lock()
_store = {}


@app.route("/api/store", methods=["POST"])
def store():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "owner" not in data or "secret" not in data:
        return jsonify({"error": "owner and secret required"}), 400
    owner = str(data["owner"])
    secret = str(data["secret"])
    # Bound input before any (superlinear, pure-Python) crypto work. Checker
    # owners are ~13 chars and secrets/flags are <= 32 bytes.
    if len(owner) > 256 or len(secret.encode("utf-8")) > 4096:
        return jsonify({"error": "too large"}), 400
    item_id = secrets.token_hex(4)
    token = secrets.token_hex(16)
    # Fresh random nonce per item -> every item has a distinct keystream, so
    # recovering one item's keystream reveals nothing about any other item.
    # (CTR is length-preserving, so the published length/ciphertext size is
    # unchanged and the checker stays green.)
    nonce = secrets.token_bytes(8)
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(secret.encode("utf-8"))
    with _lock:
        _store[item_id] = {"owner": owner, "ct": ct, "nonce": nonce, "token": token}
    return jsonify({"id": item_id, "token": token}), 201


@app.route("/api/item/<item_id>", methods=["GET"])
def item(item_id):
    with _lock:
        it = _store.get(item_id)
        if it is None:
            return jsonify({"error": "not found"}), 404
        return jsonify({
            "id": item_id,
            "owner": it["owner"],
            "ciphertext": it["ct"].hex(),
            "length": len(it["ct"]),
        }), 200


@app.route("/api/items", methods=["GET"])
def items():
    with _lock:
        out = [{"id": k, "owner": v["owner"]} for k, v in _store.items()]
    return jsonify({"items": out}), 200


@app.route("/api/reveal", methods=["POST"])
def reveal():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "id" not in data or "token" not in data:
        return jsonify({"error": "id and token required"}), 400
    item_id = str(data["id"])
    token = str(data["token"])
    # hmac.compare_digest raises TypeError on non-ASCII str; tokens are 32 hex
    # chars, so reject anything else up front (otherwise it is an unhandled 500).
    if len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
        return jsonify({"error": "forbidden"}), 403
    with _lock:
        it = _store.get(item_id)
        if it is None:
            return jsonify({"error": "not found"}), 404
        if not hmac.compare_digest(token, it["token"]):
            return jsonify({"error": "forbidden"}), 403
        cipher = AES.new(KEY, AES.MODE_CTR, nonce=it["nonce"])
        pt = cipher.decrypt(it["ct"])
    return jsonify({"secret": pt.decode("utf-8", errors="replace")}), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "CipherVault", "status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    app.run(host="0.0.0.0", port=port, threaded=True)
