#!/usr/bin/env python3
"""Traffic intel — find who is exploiting your services, and with what.

Reads a classic pcap, reconstructs the TCP connections to YOUR service ports, and
reports which source IPs pulled FLAGS out of your services plus the request bytes
that did it. That request IS the attacker's exploit: patch the hole it hits, and
replay the same request against everyone else.

    python defense/trafmon.py cap.pcap --service-ports 5001,5002,5003 \
        [--exclude-ip 10.60.0.1] [--flag-regex '[A-Z0-9]{31}='] \
        [--save-exploits dir] [--min-flags 1]

Capture on your vulnbox, e.g.:
    sudo tcpdump -i any -s0 -w cap.pcap tcp
(This reads classic pcap. Wireshark writes pcapng -> convert:
    tshark -F pcap -r in.pcapng -w cap.pcap )
"""
import argparse
import collections
import os
import re
import struct
import sys


def parse_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        raise ValueError("file too short to be a pcap")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        en = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        en = "<"
    else:
        raise ValueError("not a classic pcap (magic %r). Convert pcapng: "
                         "tshark -F pcap -r in.pcapng -w cap.pcap" % (magic,))
    _, _, _, _, _, network = struct.unpack(en + "HHiIII", data[4:24])
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(en + "IIII", data[off:off + 16])
        off += 16
        if incl < 0 or off + incl > len(data):
            break
        p = _decode(data[off:off + incl], network)
        off += incl
        if p:
            p["ts"] = ts_sec + ts_usec / 1e6
            pkts.append(p)
    return pkts


def _decode(raw, linktype):
    try:
        if linktype == 1:                      # Ethernet
            if len(raw) < 14:
                return None
            eth = struct.unpack(">H", raw[12:14])[0]
            o = 14
            while eth == 0x8100 and len(raw) >= o + 4:   # VLAN tag(s)
                eth = struct.unpack(">H", raw[o + 2:o + 4])[0]
                o += 4
            return _ipv4(raw[o:]) if eth == 0x0800 else None
        if linktype == 113:                    # Linux cooked (SLL)
            if len(raw) < 16:
                return None
            return _ipv4(raw[16:]) if struct.unpack(">H", raw[14:16])[0] == 0x0800 else None
        if linktype == 276:                    # Linux cooked v2 (SLL2)
            if len(raw) < 20:
                return None
            return _ipv4(raw[20:]) if struct.unpack(">H", raw[0:2])[0] == 0x0800 else None
        if linktype in (101, 12):              # raw IP
            return _ipv4(raw)
    except Exception:
        return None
    return None


def _ipv4(b):
    if len(b) < 20 or (b[0] >> 4) != 4:
        return None
    ihl = (b[0] & 0x0f) * 4
    if b[9] != 6:                              # TCP only
        return None
    src = ".".join(map(str, b[12:16]))
    dst = ".".join(map(str, b[16:20]))
    tcp = b[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    doff = (tcp[12] >> 4) * 4
    return {"src": src, "sport": sport, "dst": dst, "dport": dport, "payload": tcp[doff:]}


def _preview(b, limit=500):
    b = b[:limit]
    t = b.decode("latin-1")
    t = "".join(ch if (32 <= ord(ch) < 127 or ch in "\r\n\t") else "." for ch in t)
    return "    | " + t.replace("\r", "").replace("\n", "\n    | ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--service-ports", required=True, help="comma list of YOUR service ports")
    ap.add_argument("--flag-regex", default=r"[A-Z0-9]{31}=")
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="checker/your own ip(s) to not report as attackers (repeatable)")
    ap.add_argument("--min-flags", type=int, default=1)
    ap.add_argument("--save-exploits", help="dir to write one sample exploit request per (ip,port)")
    args = ap.parse_args()

    ports = set(int(x) for x in args.service_ports.split(",") if x.strip())
    fre = re.compile(args.flag_regex.encode())
    pkts = parse_pcap(args.pcap)

    # reassemble per connection, split by direction using the known service port
    conns = collections.OrderedDict()
    for p in pkts:
        if p["dport"] in ports:
            client, server, direction, svc = (p["src"], p["sport"]), (p["dst"], p["dport"]), "c2s", p["dport"]
        elif p["sport"] in ports:
            client, server, direction, svc = (p["dst"], p["dport"]), (p["src"], p["sport"]), "s2c", p["sport"]
        else:
            continue
        c = conns.setdefault((client, server), {"svc": svc, "c2s": b"", "s2c": b""})
        c[direction] += p["payload"]

    # a flag in s2c (response FROM your service) == the client pulled a flag out
    agg = collections.defaultdict(lambda: {"flags": set(), "reqs": []})
    for (client, _server), c in conns.items():
        flags = set(m.group(0).decode() for m in fre.finditer(c["s2c"]))
        if not flags or client[0] in args.exclude_ip:
            continue
        a = agg[(client[0], c["svc"])]
        a["flags"].update(flags)
        if c["c2s"]:
            a["reqs"].append(c["c2s"])

    print("=== %d packets, %d connection(s) to ports %s ==="
          % (len(pkts), len(conns), sorted(ports)))
    print("=== flags pulled OUT of your services (likely attackers) ===")
    if args.exclude_ip:
        print("    (ignoring source ip(s): %s)" % ", ".join(args.exclude_ip))
    rows = sorted(agg.items(), key=lambda kv: len(kv[1]["flags"]), reverse=True)
    shown = 0
    for (ip, port), info in rows:
        if len(info["flags"]) < args.min_flags:
            continue
        shown += 1
        req = info["reqs"][0] if info["reqs"] else b""
        print("\n[!] %-15s -> :%-5d  stole %d flag(s)" % (ip, port, len(info["flags"])))
        print("    sample exploit request (%d bytes):" % len(req))
        print(_preview(req))
        if args.save_exploits and req:
            os.makedirs(args.save_exploits, exist_ok=True)
            fn = os.path.join(args.save_exploits, "exploit_%s_%d.bin" % (ip.replace(".", "_"), port))
            open(fn, "wb").write(req)
            print("    saved request -> %s  (replay it against other teams)" % fn)
    if not shown:
        print("  (no flags seen leaving your services in this capture)")


if __name__ == "__main__":
    main()
