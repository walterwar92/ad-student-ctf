#!/usr/bin/env python3
r"""Stopgap mitigation proxy (a quick WAF while you write the real patch).

Forwards TCP from a public port to your real service, but DROPS any connection
whose client->server bytes match an exploit signature. Works for HTTP and raw-TCP
services alike (it matches on raw bytes).

    python defense/filter_proxy.py --listen 0.0.0.0:6001 --target 127.0.0.1:5001 \
        --block "UNION SELECT" --block-re "\.\./" [--ci] [--mode reset|drop]

Deploy: move the real service to an inner port and run this on the public one
(on the real box, or redirect with iptables). Keep signatures NARROW so the
checker's legitimate traffic still passes -- watch your SLA after enabling.

This buys time; it does not replace the patch (attackers can morph payloads).
"""
import argparse
import os
import re
import socket
import threading
import time

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filter.log")
OVERLAP = 128  # bytes carried between chunks so a signature split across packets still matches


def log(msg):
    line = time.strftime("%H:%M:%S ") + msg
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def build_matchers(subs, res, ci):
    flags = re.IGNORECASE if ci else 0
    pats = [re.compile(re.escape(s.encode()), flags) for s in subs]
    pats += [re.compile(r.encode(), flags) for r in res]
    return pats


def handle(client, addr, target, pats, mode, max_scan):
    try:
        server = socket.create_connection(target, timeout=5)
    except Exception as e:
        log("upstream down (%r); dropping %s:%d" % (e, addr[0], addr[1]))
        client.close()
        return

    def c2s():
        scanned = 0
        tail = b""
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                if scanned < max_scan:
                    window = tail + data
                    for p in pats:
                        m = p.search(window)
                        if m:
                            log("BLOCK %s:%d -> :%d  matched %r"
                                % (addr[0], addr[1], target[1], m.group(0)[:48]))
                            try:
                                server.close()
                            finally:
                                client.close()
                            return
                    tail = data[-OVERLAP:]
                    scanned += len(data)
                server.sendall(data)
        except Exception:
            pass
        finally:
            try:
                server.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def s2c():
        try:
            while True:
                data = server.recv(65536)
                if not data:
                    break
                client.sendall(data)
        except Exception:
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=c2s, daemon=True)
    t2 = threading.Thread(target=s2c, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (client, server):
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="host:port to listen on (the public port)")
    ap.add_argument("--target", required=True, help="host:port of the real service")
    ap.add_argument("--block", action="append", default=[], help="literal substring to block (repeatable)")
    ap.add_argument("--block-re", action="append", default=[], help="regex to block (repeatable)")
    ap.add_argument("--ci", action="store_true", help="case-insensitive matching")
    ap.add_argument("--mode", choices=["reset", "drop"], default="reset",
                    help="reset = close both sides; drop = same here (connection is cut either way)")
    ap.add_argument("--max-scan", type=int, default=65536, help="bytes of each connection to scan")
    args = ap.parse_args()

    lh, lp = args.listen.rsplit(":", 1)
    th, tp = args.target.rsplit(":", 1)
    target = (th, int(tp))
    pats = build_matchers(args.block, args.block_re, args.ci)
    if not pats:
        log("WARNING: no --block/--block-re signatures; everything will pass through")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, int(lp)))
    srv.listen(128)
    log("filter up: %s -> %s | %d signature(s), mode=%s" % (args.listen, args.target, len(pats), args.mode))
    try:
        while True:
            c, addr = srv.accept()
            threading.Thread(target=handle, args=(c, addr, target, pats, args.mode, args.max_scan),
                             daemon=True).start()
    except KeyboardInterrupt:
        log("stopping")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
