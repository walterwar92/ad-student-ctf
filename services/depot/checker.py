import json
import random
import re
import socket
import string

SERVICE = "depot"
DEFAULT_PORT = 5003

OK = 101
CORRUPT = 102
MUMBLE = 103
DOWN = 104
CHECKER_ERROR = 110

TIMEOUT = 5.0
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")


class Client:
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
        try:
            self.sock.sendall(b"QUIT\n")
        except Exception:
            pass
        try:
            self.rf.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def rand_str(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def rand_user():
    return "u" + rand_str(15)


def rand_key():
    return "k" + rand_str(15)


def rand_value():
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(24))


def check(host, port):
    try:
        c = Client(host, port)
    except (OSError, socket.timeout):
        return DOWN
    try:
        user = rand_user()
        pw = rand_str(16)
        key = rand_key()
        val = rand_value()

        c.sendline("REGISTER {} {}".format(user, pw))
        r = c.readline()
        if not r.startswith("OK "):
            return MUMBLE
        token = r[3:].strip()
        if not token:
            return MUMBLE

        c.sendline("PUT {} {} {}".format(token, key, val))
        r = c.readline()
        if r != "OK":
            return MUMBLE

        c.sendline("GET {} {}".format(token, key))
        r = c.readline()
        if not r.startswith("OK "):
            return MUMBLE
        if r[3:] != val:
            return MUMBLE

        c.sendline("LIST {}".format(token))
        r = c.readline()
        if not r.startswith("OK"):
            return MUMBLE
        listed = r[2:].strip()
        keys = listed.split(",") if listed else []
        if key not in keys:
            return MUMBLE

        c.sendline("PING")
        r = c.readline()
        if r != "PONG":
            return MUMBLE

        return OK
    except (EOFError, OSError, socket.timeout):
        return DOWN
    except Exception:
        return MUMBLE
    finally:
        c.close()


def put(host, port, flag):
    try:
        c = Client(host, port)
    except (OSError, socket.timeout):
        return (DOWN, "", "")
    try:
        user = rand_user()
        pw = rand_str(16)
        key = rand_key()

        c.sendline("REGISTER {} {}".format(user, pw))
        r = c.readline()
        if not r.startswith("OK "):
            return (MUMBLE, "", "")
        token = r[3:].strip()
        if not token:
            return (MUMBLE, "", "")

        c.sendline("PUT {} {} {}".format(token, key, flag))
        r = c.readline()
        if r != "OK":
            return (MUMBLE, "", "")

        flag_id = "{}/{}".format(user, key)
        private = json.dumps({"user": user, "pass": pw})
        return (OK, flag_id, private)
    except (EOFError, OSError, socket.timeout):
        return (DOWN, "", "")
    except Exception:
        return (MUMBLE, "", "")
    finally:
        c.close()


def get(host, port, flag_id, flag, private):
    try:
        info = json.loads(private)
        user = info["user"]
        pw = info["pass"]
    except Exception:
        return CHECKER_ERROR
    try:
        _, key = flag_id.split("/", 1)
    except ValueError:
        return CHECKER_ERROR

    try:
        c = Client(host, port)
    except (OSError, socket.timeout):
        return DOWN
    try:
        c.sendline("AUTH {} {}".format(user, pw))
        r = c.readline()
        if not r.startswith("OK "):
            return MUMBLE
        token = r[3:].strip()
        if not token:
            return MUMBLE

        c.sendline("GET {} {}".format(token, key))
        r = c.readline()
        if r.startswith("OK "):
            value = r[3:]
            if value == flag:
                return OK
            return CORRUPT
        if r.startswith("ERR notfound"):
            return CORRUPT
        return MUMBLE
    except (EOFError, OSError, socket.timeout):
        return DOWN
    except Exception:
        return MUMBLE
    finally:
        c.close()


if __name__ == "__main__":
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    print("check ->", check(host, port))
