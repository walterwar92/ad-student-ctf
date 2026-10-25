#!/usr/bin/env python3
"""checkerwatch — identify the CHECKER at round start, remember it, then listen
with filters and flag live attackers. Stdlib only; reuses trafmon's decoders.

Idea (reliable on any ForcAD-style A&D):
  * the CHECKER is the only source that PLANTS flags — a valid flag shows up in
    its client->service bytes (its `put`). Attackers can't plant; a flag only
    ever appears in their service->client bytes (what they stole). So:
        flag in c2s  => that source is the checker   (remember its IP)
        flag in s2c  => that source pulled a flag out => attacker (if not checker)
  * corroborated by cadence: the checker hits every service every tick from a
    stable IP. The identified checker IP(s) are persisted to a state file and
    survive restarts (so you "remember" it for the whole game).

Run ON your vulnbox at the start of the test round:

    # live (Linux; needs tcpdump + root):
    sudo python3 defense/checkerwatch.py --service-ports 5001,5002,5003 \
         --my-ip 10.60.1.2 --save-exploits defense/live_exploits

    # offline (anywhere) over a capture you already have:
    python defense/checkerwatch.py --pcap cap.pcap --service-ports 5001,5002,5003

Once the checker is known, feed it straight into trafmon:
    python defense/trafmon.py cap.pcap --service-ports P1,P2 --exclude-ip <checker>
"""
import argparse
import collections
import json
import os
import re
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trafmon  # noqa: E402  (reuse _decode/_ipv4/_preview/parse_pcap)

MAXBUF = 1 << 16  # cap reassembly buffer per direction (flags are tiny)


class Watch:
    def __init__(self, ports, flag_re, my_ips, state_path, save_dir, min_plant, quiet):
        self.ports = ports
        self.fre = re.compile(flag_re.encode())
        self.my_ips = set(my_ips or [])
        self.state_path = state_path
        self.save_dir = save_dir
        self.min_plant = min_plant
        self.quiet = quiet
        self.conns = {}                       # (cli,cport,svcport) -> {"c2s","s2c","cf","sf"}
        self.ip = collections.defaultdict(lambda: {   # per source ip
            "plant": set(), "steal": set(), "svcs": set(), "conns": 0,
            "first": None, "last": None})
        self.checkers = set()
        self.reported = set()                 # (ip,port) attacker rows already announced
        self._load_state()

    # ---- persistence: remember the checker across restarts ----
    def _load_state(self):
        try:
            with open(self.state_path, encoding="utf-8") as f:
                st = json.load(f)
            self.checkers = set(st.get("checker_ips", []))
            if self.checkers and not self.quiet:
                print("[checkerwatch] remembered checker(s) from %s: %s"
                      % (self.state_path, ", ".join(sorted(self.checkers))))
        except Exception:
            pass

    def _save_state(self):
        st = {"checker_ips": sorted(self.checkers),
              "service_ports": sorted(self.ports),
              "updated": int(time.time()),
              "evidence": {ip: {"planted": len(self.ip[ip]["plant"]),
                                "services": sorted(self.ip[ip]["svcs"])}
                           for ip in self.checkers}}
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, indent=2)
        os.replace(tmp, self.state_path)

    # ---- packet intake ----
    def feed(self, p):
        dport, sport = p["dport"], p["sport"]
        if dport in self.ports:
            cli, cport, svc, direction = p["src"], p["sport"], dport, "c2s"
        elif sport in self.ports:
            cli, cport, svc, direction = p["dst"], p["dport"], sport, "s2c"
        else:
            return
        key = (cli, cport, svc)
        c = self.conns.get(key)
        if c is None:
            c = self.conns[key] = {"c2s": b"", "s2c": b"", "cf": set(), "sf": set()}
            self.ip[cli]["conns"] += 1
        if p["payload"]:
            c[direction] = (c[direction] + p["payload"])[-MAXBUF:]
        ts = p.get("ts") or time.time()
        st = self.ip[cli]
        st["first"] = st["first"] or ts
        st["last"] = ts
        st["svcs"].add(svc)

        # new flags in each direction?
        newc = set(m.group(0).decode() for m in self.fre.finditer(c["c2s"])) - c["cf"]
        news = set(m.group(0).decode() for m in self.fre.finditer(c["s2c"])) - c["sf"]
        if newc:
            c["cf"] |= newc
            st["plant"] |= newc                       # planted flags => checker signal
            self._maybe_mark_checker(cli)
        if news:
            c["sf"] |= news
            st["steal"] |= news
            self._maybe_report_attacker(cli, svc, c)

    # ---- checker identification ----
    def _maybe_mark_checker(self, ip):
        if ip in self.checkers:
            return
        st = self.ip[ip]
        if len(st["plant"]) >= self.min_plant and len(st["svcs"]) >= min(2, len(self.ports)):
            self.checkers.add(ip)
            self._save_state()
            if not self.quiet:
                print("\n[checkerwatch] *** CHECKER IDENTIFIED: %s *** "
                      "(planted %d flag(s) across services %s) -> remembered in %s\n"
                      % (ip, len(st["plant"]), sorted(st["svcs"]), self.state_path))

    # ---- live attacker reporting (filtered) ----
    def _maybe_report_attacker(self, ip, svc, conn):
        if ip in self.checkers or ip in self.my_ips:
            return                                    # filter: never flag checker / self
        stolen = conn["sf"] - self.ip[ip]["plant"]    # flags it got out but never planted
        if not stolen:
            return
        row = (ip, svc)
        n = len(self.ip[ip]["steal"])
        tag = "NEW" if row not in self.reported else "+"
        self.reported.add(row)
        print("[ATTACK %s] %-15s -> :%-5d stole %d flag(s) total" % (tag, ip, svc, n))
        if self.save_dir and conn["c2s"] and tag == "NEW":
            os.makedirs(self.save_dir, exist_ok=True)
            fn = os.path.join(self.save_dir, "exploit_%s_%d.bin" % (ip.replace(".", "_"), svc))
            with open(fn, "wb") as f:
                f.write(conn["c2s"])
            print("    saved exploit request -> %s  (replay it against other teams)" % fn)
            print(trafmon._preview(conn["c2s"]))

    # ---- summary ----
    def summary(self):
        print("\n=== checkerwatch summary ===")
        print("checker(s): %s" % (", ".join(sorted(self.checkers)) or "(none yet)"))
        atk = [(ip, s) for ip, s in self.ip.items()
               if ip not in self.checkers and ip not in self.my_ips and s["steal"]]
        atk.sort(key=lambda kv: len(kv[1]["steal"]), reverse=True)
        print("attackers seen: %d" % len(atk))
        for ip, s in atk:
            print("  %-15s stole %d flag(s) from services %s" % (ip, len(s["steal"]), sorted(s["svcs"])))


def run_offline(w, path):
    for p in trafmon.parse_pcap(path):
        w.feed(p)
    w.summary()


def run_live(w, iface, status_every):
    bpf = "tcp and (" + " or ".join("port %d" % p for p in sorted(w.ports)) + ")"
    cmd = ["tcpdump", "-i", iface, "-n", "-s", "0", "-U", "-w", "-", bpf]
    print("[checkerwatch] live: %s" % " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    f = proc.stdout
    hdr = f.read(24)
    if len(hdr) < 24:
        print("tcpdump produced no pcap header (need root? wrong iface?)", file=sys.stderr)
        return
    magic = hdr[:4]
    en = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
    linktype = struct.unpack(en + "I", hdr[20:24])[0]
    last = time.time()
    try:
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_usec, incl, _orig = struct.unpack(en + "IIII", rh)
            body = f.read(incl)
            if len(body) < incl:
                break
            p = trafmon._decode(body, linktype)
            if p:
                p["ts"] = ts_sec + ts_usec / 1e6
                w.feed(p)
            if status_every and time.time() - last >= status_every:
                last = time.time()
                print("[checkerwatch] %s | checker=%s | attackers=%d"
                      % (time.strftime("%H:%M:%S"), ",".join(sorted(w.checkers)) or "?",
                         sum(1 for ip, s in w.ip.items()
                             if ip not in w.checkers and ip not in w.my_ips and s["steal"])))
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        w.summary()


def main():
    ap = argparse.ArgumentParser(description="identify the checker, remember it, listen for attackers")
    ap.add_argument("--service-ports", required=True, help="comma list of YOUR service ports")
    ap.add_argument("--pcap", help="offline: parse this capture instead of sniffing live")
    ap.add_argument("--iface", default="any", help="live capture interface (default: any)")
    ap.add_argument("--flag-regex", default=r"[A-Z0-9]{31}=")
    ap.add_argument("--my-ip", action="append", default=[], help="your own box ip(s) to ignore (repeatable)")
    ap.add_argument("--min-plant", type=int, default=2, help="flags a source must plant to be ruled checker")
    ap.add_argument("--state", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "checker.json"),
                    help="where the identified checker is remembered")
    ap.add_argument("--save-exploits", help="dir to save captured attacker requests for replay")
    ap.add_argument("--status-every", type=int, default=30, help="live: print a heartbeat every N s (0=off)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    ports = set(int(x) for x in args.service_ports.split(",") if x.strip())
    w = Watch(ports, args.flag_regex, args.my_ip, args.state, args.save_exploits, args.min_plant, args.quiet)
    if args.pcap:
        run_offline(w, args.pcap)
    else:
        run_live(w, args.iface, args.status_every)


if __name__ == "__main__":
    main()
