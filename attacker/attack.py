#!/usr/bin/env python3
"""Reference attack farm.

Pulls the public flag ids from the scoreboard, runs each service's reference
exploit against every ENEMY team, collects the stolen flags, and submits them
for attack points. This is the loop every A&D team automates — read it, then
build your own / swap in your own exploits.

Run from the repo root:
    python attacker/attack.py            # one pass
    python attacker/attack.py --loop     # forever, every TICK_SECONDS
    python attacker/attack.py --service web --team team3   # narrow it down

Needs:  pip install requests
"""
import argparse
import hmac
import hashlib
import importlib.util
import os
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# host port scheme — must match gen_compose.py
PORT_BASE = {"web": 9300, "crypto": 9400, "depot": 9500}


def read_env(path=None):
    env = {}
    path = path or os.path.join(ROOT, ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


ENV = read_env()
GAME_SECRET = ENV.get("GAME_SECRET", "studentctf-local-dev-change-me")
MY_TEAM = ENV.get("MY_TEAM", "team1")
SCOREBOARD = os.environ.get("SCOREBOARD_URL") or "http://127.0.0.1:%s" % ENV.get("SCOREBOARD_PORT", "8090")


def my_token():
    return hmac.new(GAME_SECRET.encode(), MY_TEAM.encode(), hashlib.sha256).hexdigest()[:16]


def load_sploit(service):
    path = os.path.join(ROOT, "services", service, "sploit.py")
    spec = importlib.util.spec_from_file_location("sploit_%s" % service, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def team_index(name):
    # "team7" -> 7
    digits = "".join(ch for ch in name if ch.isdigit())
    return int(digits) if digits else None


def run_pass(only_service=None, only_team=None):
    try:
        r = requests.get(SCOREBOARD + "/api/flag_ids", timeout=5)
        flag_ids = r.json().get("flag_ids", {})
    except Exception as e:  # noqa: BLE001
        print("[!] cannot reach scoreboard at %s (%r). Is the stand up?" % (SCOREBOARD, e))
        return

    sploits = {}
    stolen = []
    for team, svcmap in flag_ids.items():
        if team == MY_TEAM:
            continue  # never attack yourself
        if only_team and team != only_team:
            continue
        idx = team_index(team)
        if idx is None:
            continue
        for service, fids in svcmap.items():
            if only_service and service != only_service:
                continue
            if service not in PORT_BASE:
                continue
            if service not in sploits:
                try:
                    sploits[service] = load_sploit(service)
                except Exception as e:  # noqa: BLE001
                    print("[!] no exploit for %s yet (%r)" % (service, e))
                    sploits[service] = None
            mod = sploits[service]
            if mod is None:
                continue
            host, port = "127.0.0.1", PORT_BASE[service] + idx
            for fid in fids:
                try:
                    flags = mod.exploit(host, port, fid) or []
                except Exception as e:  # noqa: BLE001
                    print("    [x] %-6s %s id=%s -> %r" % (service, team, fid, e))
                    continue
                for f in flags:
                    stolen.append(f)
                    print("    [+] %-6s %s id=%-20s -> %s" % (service, team, fid, f))

    stolen = list(dict.fromkeys(stolen))  # de-dup, keep order
    if not stolen:
        print("[*] nothing stolen this pass.")
        return
    submit(stolen)


def submit(flags):
    try:
        r = requests.post(SCOREBOARD + "/flags",
                          data="\n".join(flags),
                          headers={"X-Team-Token": my_token()},
                          timeout=10)
    except Exception as e:  # noqa: BLE001
        print("[!] submit failed: %r" % e)
        return
    verdicts = {}
    for line in r.text.splitlines():
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            verdicts[parts[1]] = verdicts.get(parts[1], 0) + 1
    summary = ", ".join("%s=%d" % kv for kv in sorted(verdicts.items()))
    print("[=] submitted %d flag(s): %s" % (len(flags), summary or r.text.strip()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="run forever")
    ap.add_argument("--interval", type=int, default=int(ENV.get("TICK_SECONDS", "30")))
    ap.add_argument("--service", choices=list(PORT_BASE), help="only this service")
    ap.add_argument("--team", help="only this team, e.g. team3")
    args = ap.parse_args()

    print("[*] attacker=%s  token=%s  scoreboard=%s" % (MY_TEAM, my_token(), SCOREBOARD))
    while True:
        print("-" * 60)
        run_pass(args.service, args.team)
        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
