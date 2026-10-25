"""Black-box checker for the SecureNotes (web) service.

Talks to the service only over its public HTTP interface.
"""
import json
import random
import re
import string

import requests

SERVICE = "web"
DEFAULT_PORT = 5001

TIMEOUT = 5

# status codes
OK = 101
CORRUPT = 102
MUMBLE = 103
DOWN = 104
CHECKER_ERROR = 110

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")


def _rand(n=12):
    alphabet = string.ascii_lowercase + string.digits
    # ensure it starts with a letter so it is a valid-ish username
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice(alphabet) for _ in range(n - 1)
    )


def _base(host, port):
    return "http://%s:%d" % (host, port)


def check(host, port):
    base = _base(host, port)
    try:
        u = _rand()
        p = _rand(16)
        r = requests.post(base + "/api/register",
                          json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code != 201:
            return MUMBLE
        token = r.json().get("token")
        if not token:
            return MUMBLE
        headers = {"Authorization": "Bearer " + token}

        title = _rand(8)
        body = _rand(24)
        r = requests.post(base + "/api/notes",
                          json={"title": title, "body": body},
                          headers=headers, timeout=TIMEOUT)
        if r.status_code != 201 or "id" not in r.json():
            return MUMBLE

        r = requests.get(base + "/api/notes", headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        notes = r.json().get("notes")
        if not isinstance(notes, list) or not any(n.get("body") == body for n in notes):
            return MUMBLE

        # benign search must find the note we just created
        sub = body[6:14]
        r = requests.get(base + "/api/notes/search",
                         params={"q": sub}, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        snotes = r.json().get("notes")
        if not isinstance(snotes, list) or not any(n.get("body") == body for n in snotes):
            return MUMBLE

        return OK
    except requests.exceptions.RequestException:
        return DOWN
    except (ValueError, KeyError, TypeError, AttributeError):
        return MUMBLE
    except Exception:
        return CHECKER_ERROR


def put(host, port, flag):
    base = _base(host, port)
    try:
        u = _rand()
        p = _rand(16)
        r = requests.post(base + "/api/register",
                          json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code != 201 or not r.json().get("token"):
            return (MUMBLE, "", "")

        r = requests.post(base + "/api/login",
                          json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code != 200:
            return (MUMBLE, "", "")
        token = r.json().get("token")
        if not token:
            return (MUMBLE, "", "")
        headers = {"Authorization": "Bearer " + token}

        title = _rand(8)
        r = requests.post(base + "/api/notes",
                          json={"title": title, "body": flag},
                          headers=headers, timeout=TIMEOUT)
        if r.status_code != 201 or "id" not in r.json():
            return (MUMBLE, "", "")

        # flag_id is the public username; private holds the credentials
        return (OK, u, json.dumps({"u": u, "p": p}))
    except requests.exceptions.RequestException:
        return (DOWN, "", "")
    except (ValueError, KeyError, TypeError, AttributeError):
        return (MUMBLE, "", "")
    except Exception:
        return (CHECKER_ERROR, "", "")


def get(host, port, flag_id, flag, private):
    base = _base(host, port)
    try:
        info = json.loads(private)
        u = info["u"]
        p = info["p"]
    except (ValueError, KeyError, TypeError):
        return CHECKER_ERROR
    try:
        r = requests.post(base + "/api/login",
                          json={"username": u, "password": p}, timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        token = r.json().get("token")
        if not token:
            return MUMBLE
        headers = {"Authorization": "Bearer " + token}

        r = requests.get(base + "/api/notes", headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        notes = r.json().get("notes")
        if not isinstance(notes, list):
            return MUMBLE
        if any(n.get("body") == flag for n in notes):
            return OK
        return CORRUPT
    except requests.exceptions.RequestException:
        return DOWN
    except (ValueError, KeyError, TypeError, AttributeError):
        return MUMBLE
    except Exception:
        return CHECKER_ERROR


if __name__ == "__main__":
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    pt = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    print("check:", check(h, pt))
