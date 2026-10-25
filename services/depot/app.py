import hashlib
import hmac
import os
import socketserver
import secrets
import threading

DEFAULT_PORT = 5003
BASE = os.path.join("data", "depot")

LOCK = threading.Lock()
TOKENS = {}   # token -> user
USERS = {}    # user -> password

MAX_LINE = 65536


def safe_name(name):
    if not name:
        return False
    if "\x00" in name:          # NUL would bypass the checks below and crash open()
        return False
    if "/" in name or "\\" in name:
        return False
    if ".." in name:
        return False
    if name.startswith("."):
        return False
    return True


def _pass_path(user):
    return os.path.join(BASE, user, ".pass")


def _hash_pw(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def register(user, password):
    if not safe_name(user):
        return "ERR badname"
    with LOCK:
        udir = os.path.join(BASE, user)
        # Refuse if the account exists in memory OR already has a directory on
        # disk. Accounts live only in RAM, but flag files persist on disk; after
        # any restart (patch redeploy / supervisor / round reset) USERS is empty,
        # so without the on-disk check a rival could re-REGISTER a victim's name,
        # reuse its existing flag files, and read the flag. Persisting the
        # (hashed) password also keeps AUTH working across restarts (SLA).
        if user in USERS or os.path.isdir(udir):
            return "ERR exists"
        pw_hash = _hash_pw(password)
        try:
            os.makedirs(udir, exist_ok=True)
            with open(_pass_path(user), "w", encoding="utf-8") as fh:
                fh.write(pw_hash)
        except OSError:
            return "ERR io"
        USERS[user] = pw_hash
        token = secrets.token_hex(16)
        TOKENS[token] = user
        return "OK " + token


def auth(user, password):
    with LOCK:
        stored = USERS.get(user)
        if stored is None:
            # Repopulate from the persisted credential so AUTH (and the checker's
            # get()) keep working after a restart.
            try:
                with open(_pass_path(user), "r", encoding="utf-8") as fh:
                    stored = fh.read().strip()
            except OSError:
                stored = None
            if stored:
                USERS[user] = stored
        if stored is None or not hmac.compare_digest(stored, _hash_pw(password)):
            return "ERR badcreds"
        token = secrets.token_hex(16)
        TOKENS[token] = user
        return "OK " + token


def put(token, key, value):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    if not safe_name(key):
        return "ERR badkey"
    if len(value) > 4096:          # bound disk use; checker values are ~24 bytes
        return "ERR toobig"
    path = os.path.join(BASE, user, key)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value)
    except OSError:
        return "ERR io"
    return "OK"


def get(token, key):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    if not safe_name(key):   # reject "/", "\", "..", leading "." -> closes path traversal (CWE-22)
        return "ERR notfound"
    path = os.path.join(BASE, user, key)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError:
        return "ERR notfound"
    return "OK " + value


def list_keys(token):
    with LOCK:
        user = TOKENS.get(token)
    if user is None:
        return "ERR badtoken"
    directory = os.path.join(BASE, user)
    try:
        names = sorted(n for n in os.listdir(directory) if not n.startswith("."))
    except OSError:
        names = []
    return "OK " + ",".join(names)


def dispatch(line):
    parts = line.split()
    if not parts:
        return "ERR empty", False
    cmd = parts[0].upper()

    if cmd == "PING":
        return "PONG", False
    if cmd == "QUIT":
        return "BYE", True
    if cmd == "REGISTER":
        p = line.split(maxsplit=2)
        if len(p) != 3:
            return "ERR usage", False
        return register(p[1], p[2]), False
    if cmd == "AUTH":
        p = line.split(maxsplit=2)
        if len(p) != 3:
            return "ERR usage", False
        return auth(p[1], p[2]), False
    if cmd == "PUT":
        p = line.split(maxsplit=3)
        if len(p) != 4:
            return "ERR usage", False
        return put(p[1], p[2], p[3]), False
    if cmd == "GET":
        p = line.split(maxsplit=2)
        if len(p) != 3:
            return "ERR usage", False
        return get(p[1], p[2]), False
    if cmd == "LIST":
        p = line.split(maxsplit=1)
        if len(p) != 2:
            return "ERR usage", False
        return list_keys(p[1]), False
    return "ERR unknown", False


_CONN_SEM = threading.BoundedSemaphore(128)   # cap concurrent conns (anti flood/slowloris); 128 >> checker's 1/round


class Handler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self):
        if not _CONN_SEM.acquire(blocking=False):
            # Shed load instead of letting thread/FD count grow without bound.
            try:
                self.wfile.write(b"ERR busy\n")
                self.wfile.flush()
            except Exception:
                pass
            return
        try:
            while True:
                raw = self.rfile.readline(MAX_LINE)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    continue
                resp, close = dispatch(line)
                self.wfile.write((resp + "\n").encode("utf-8"))
                self.wfile.flush()
                if close:
                    break
        except Exception:
            pass
        finally:
            _CONN_SEM.release()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    os.makedirs(BASE, exist_ok=True)
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    server = Server(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
