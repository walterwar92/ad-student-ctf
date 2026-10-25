"""Exploit template — copy to farm/sploits/<service>.py and fill in.

FROZEN INTERFACE (the farm calls exactly this; do not change the signature):

    def exploit(host: str, port: int, flag_id) -> list[str]
        # return the stolen flag(s) as a list of strings (may be empty).
        # flag_id is the victim's public identifier from the attack-data.
        # It may be None if the platform gives no ids — then dump whatever you can.

Rules that keep the farm healthy:
  * Use ONLY the remote network interface (no server-side secrets / local files).
  * ALWAYS set your own timeouts (sockets: settimeout; requests: timeout=...).
    The farm runs many exploits in parallel; a hang blocks a worker.
  * Never sys.exit / never raise for "nothing found" — just return [].
  * Return clean flag strings; the farm validates them against the flag regex.
  * Stdlib is safest (socket / urllib). requests is fine if installed; pwntools
    only if your attack box has it.
  * Keep it runnable standalone for quick testing:
        python farm/sploits/<service>.py <host> <port> <flag_id>
"""
import socket
import sys

TIMEOUT = 6


def exploit(host, port, flag_id):
    stolen = []
    try:
        # ---- TODO: talk to the service and steal the flag(s) ----
        # Example (raw TCP line protocol):
        # with socket.create_connection((host, port), timeout=TIMEOUT) as s:
        #     s.settimeout(TIMEOUT)
        #     s.sendall(b"...payload...\n")
        #     data = s.recv(65536).decode("utf-8", "replace")
        #     # parse flag(s) out of `data` and append to stolen
        pass
    except Exception:
        return stolen
    return stolen


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    fid = sys.argv[3] if len(sys.argv) > 3 else None
    for f in exploit(h, p, fid):
        print(f)
