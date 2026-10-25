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
    if "/" in name or "\\" in name:
        return False
    if ".." in name:
        return False
    if name.startswith("."):
        return False
    return True


def register(user, password):
    if not safe_name(user):
        return "ERR badname"
    with LOCK:
        if user in USERS:
            return "ERR exists"
        try:
            os.makedirs(os.path.join(BASE, user), exist_ok=True)
        except OSError:
            return "ERR io"
        USERS[user] = password
        token = secrets.token_hex(16)
        TOKENS[token] = user
        return "OK " + token


def auth(user, password):
    with LOCK:
        stored = USERS.get(user)
        if stored is None or stored != password:
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


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
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
