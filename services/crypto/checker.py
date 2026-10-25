import json
import random
import re
import string

import requests

SERVICE = "crypto"
DEFAULT_PORT = 5002
TIMEOUT = 5

OK = 101
CORRUPT = 102
MUMBLE = 103
DOWN = 104
CHECKER_ERROR = 110

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")


def _base(host, port):
    return "http://{}:{}".format(host, port)


def _rand_owner():
    return "user_" + "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )


def _rand_secret(n=24):
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(n)
    )


def check(host, port):
    try:
        base = _base(host, port)
        owner = _rand_owner()
        secret = _rand_secret()

        r = requests.post(base + "/api/store",
                          json={"owner": owner, "secret": secret}, timeout=TIMEOUT)
        if r.status_code != 201:
            return MUMBLE
        try:
            j = r.json()
        except ValueError:
            return MUMBLE
        if not isinstance(j, dict) or "id" not in j or "token" not in j:
            return MUMBLE
        item_id = j["id"]
        token = j["token"]

        r = requests.post(base + "/api/reveal",
                          json={"id": item_id, "token": token}, timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        try:
            j = r.json()
        except ValueError:
            return MUMBLE
        if not isinstance(j, dict) or j.get("secret") != secret:
            return MUMBLE

        r = requests.get(base + "/api/item/{}".format(item_id), timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        try:
            j = r.json()
        except ValueError:
            return MUMBLE
        if not isinstance(j, dict):
            return MUMBLE
        ct_hex = j.get("ciphertext")
        length = j.get("length")
        if not isinstance(ct_hex, str):
            return MUMBLE
        try:
            raw = bytes.fromhex(ct_hex)
        except ValueError:
            return MUMBLE
        expect_len = len(secret.encode("utf-8"))
        if len(raw) != expect_len or length != expect_len:
            return MUMBLE

        r = requests.get(base + "/api/items", timeout=TIMEOUT)
        if r.status_code != 200:
            return MUMBLE
        try:
            j = r.json()
        except ValueError:
            return MUMBLE
        items = j.get("items") if isinstance(j, dict) else None
        if not isinstance(items, list):
            return MUMBLE
        if not any(isinstance(it, dict) and it.get("id") == item_id for it in items):
            return MUMBLE

        return OK
    except requests.exceptions.RequestException:
        return DOWN
    except Exception:
        return CHECKER_ERROR


def put(host, port, flag):
    try:
        base = _base(host, port)
        owner = _rand_owner()
        r = requests.post(base + "/api/store",
                          json={"owner": owner, "secret": flag}, timeout=TIMEOUT)
        if r.status_code != 201:
            return (MUMBLE, "", "")
        try:
            j = r.json()
        except ValueError:
            return (MUMBLE, "", "")
        if not isinstance(j, dict) or "id" not in j or "token" not in j:
            return (MUMBLE, "", "")
        return (OK, j["id"], json.dumps({"token": j["token"]}))
    except requests.exceptions.RequestException:
        return (DOWN, "", "")
    except Exception:
        return (CHECKER_ERROR, "", "")


def get(host, port, flag_id, flag, private):
    try:
        base = _base(host, port)
        try:
            priv = json.loads(private)
            token = priv["token"]
        except (ValueError, KeyError, TypeError):
            return CHECKER_ERROR
        r = requests.post(base + "/api/reveal",
                          json={"id": flag_id, "token": token}, timeout=TIMEOUT)
        if r.status_code in (403, 404):
            return CORRUPT
        if r.status_code != 200:
            return MUMBLE
        try:
            j = r.json()
        except ValueError:
            return MUMBLE
        if not isinstance(j, dict) or "secret" not in j:
            return MUMBLE
        if j["secret"] != flag:
            return CORRUPT
        return OK
    except requests.exceptions.RequestException:
        return DOWN
    except Exception:
        return CHECKER_ERROR
