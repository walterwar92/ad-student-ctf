"""Spread the farm's outbound attack traffic across all WireGuard tunnels.

Enabled ONLY when the env var FARM_VPN_MARKS is set (e.g. "7425,7426,7427",
written by deploy/wg-multi/wg-multi.sh). Importing this module then monkeypatches
socket so every new outbound connection is tagged with a rotating SO_MARK; the
`ip rule fwmark <M> lookup <table>` entries wg-multi installed send each mark out
a different tunnel. Individual exploits need zero changes — they keep using plain
`socket` / `requests`.

Safe by construction:
  * does nothing unless FARM_VPN_MARKS is set and non-empty;
  * Linux-only (needs SO_MARK); no-ops cleanly elsewhere;
  * if setsockopt is denied (not root / no CAP_NET_ADMIN) it fails open — the
    connection still proceeds on the default route, just unbalanced.

Setting SO_MARK requires CAP_NET_ADMIN (root). On the team box the farm runs as
root, so this just works; otherwise it degrades to the normal single route.
"""
import itertools
import os
import socket
import sys
import threading

_SO_MARK = getattr(socket, "SO_MARK", 36)  # 36 on Linux; attr missing off-Linux


def _parse_marks(raw):
    out = []
    for tok in raw.replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok, 0))  # accepts "7425" and "0x1D01"
        except ValueError:
            pass
    return out


def enable(marks):
    if not marks or not sys.platform.startswith("linux"):
        return False
    cyc = itertools.cycle(marks)
    lock = threading.Lock()
    orig_connect = socket.socket.connect

    def connect(self, address):
        # only mark TCP/UDP inet sockets; leave unix sockets etc. alone
        try:
            if self.family in (socket.AF_INET, socket.AF_INET6):
                with lock:
                    m = next(cyc)
                self.setsockopt(socket.SOL_SOCKET, _SO_MARK, m)
        except OSError:
            pass  # fail open: no permission -> default route
        return orig_connect(self, address)

    socket.socket.connect = connect
    return True


_raw = os.environ.get("FARM_VPN_MARKS", "")
_marks = _parse_marks(_raw)
if _marks and enable(_marks):
    sys.stderr.write("[vpn_balance] round-robin SO_MARK over tunnels: %s\n"
                     % ",".join(str(m) for m in _marks))
