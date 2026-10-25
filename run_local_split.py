#!/usr/bin/env python3
"""Run the local A&D range with a realistic defense split:

    team1  (YOU)      -> patched services/   (your committed defense)
    team2..N (enemies)-> run/_vuln/services/  (vulnerable baseline, exploitable)

Same port scheme / checksystem as run_local.py, so the farm steals REAL flags
from the vulnerable enemies while team1 stays hardened. Stdlib + Flask only.

    python run_local_split.py            # TEAMS from .env (default 10)
    python run_local_split.py --teams 4
Stop with Ctrl+C.
"""
import argparse
import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PATCHED = os.path.join(ROOT, "services")                 # team1
VULN = os.path.join(ROOT, "run", "_vuln", "services")    # team2..N
SVC = [("web", 9300), ("crypto", 9400), ("depot", 9500)]
procs = []


def read_env():
    env = {}
    p = os.path.join(ROOT, ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def wait_port(port, t=15):
    end = time.time() + t
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def shutdown(*_):
    print("\nStopping %d processes..." % len(procs))
    for _n, p, _lf in procs:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    sys.exit(0)


def main():
    env = read_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--teams", type=int, default=int(env.get("TEAMS", "10")))
    args = ap.parse_args()
    n = args.teams
    sbport = env.get("SCOREBOARD_PORT", "8090")

    rundir = os.path.join(ROOT, "run")
    logdir = os.path.join(rundir, "_logs")
    os.makedirs(logdir, exist_ok=True)

    def spawn(name, argv, cwd, logname, envextra=None):
        e = dict(os.environ)
        if envextra:
            e.update(envextra)
        lf = open(os.path.join(logdir, logname), "w")
        p = subprocess.Popen(argv, cwd=cwd, env=e, stdout=lf, stderr=subprocess.STDOUT)
        procs.append((name, p, lf))

    print("Starting %d teams x 3 services (team1=PATCHED, team2..%d=VULN) + checksystem ..."
          % (n, n))
    for i in range(1, n + 1):
        src = PATCHED if i == 1 else VULN
        for svc, base in SVC:
            cwd = os.path.join(rundir, "team%d" % i, svc)
            os.makedirs(cwd, exist_ok=True)
            spawn("team%d-%s" % (i, svc),
                  [sys.executable, os.path.join(src, svc, "app.py")],
                  cwd, "team%d-%s.log" % (i, svc), {"PORT": str(base + i)})

    teams_json = json.dumps([
        {"name": "team%d" % i, "host": "127.0.0.1",
         "ports": {"web": 9300 + i, "crypto": 9400 + i, "depot": 9500 + i}}
        for i in range(1, n + 1)
    ])
    secret = env.get("GAME_SECRET", "studentctf-local-dev-change-me")
    my_team = env.get("MY_TEAM", "team1")
    # checksystem must plant/check against the SAME code each team runs; it reads
    # SERVICES_DIR only for check logic, which is identical across patched/vuln.
    spawn("checksystem", [sys.executable, "app.py"],
          os.path.join(ROOT, "infra", "checksystem"), "checksystem.log",
          {"TEAMS_JSON": teams_json,
           "SERVICES_DIR": PATCHED,
           "DATA_DIR": os.path.join(rundir, "_checksystem"),
           "SCOREBOARD_PORT": sbport, "GAME_SECRET": secret, "MY_TEAM": my_team,
           "TICK_SECONDS": env.get("TICK_SECONDS", "30"),
           "FLAG_LIFETIME_TICKS": env.get("FLAG_LIFETIME_TICKS", "5")})

    up = wait_port(int(sbport))
    for svc, base in SVC:
        wait_port(base + 2)
    token = hmac.new(secret.encode(), my_team.encode(), hashlib.sha256).hexdigest()[:16]
    print("\n" + "=" * 60)
    print("  Scoreboard : http://127.0.0.1:%s   %s" % (sbport, "(up)" if up else "(NOT up)"))
    print("  Defense    : team1 PATCHED   Enemies: team2..team%d VULNERABLE" % n)
    print("  Your token : %s" % token)
    print("  Logs       : run/_logs/    |    Stop: Ctrl+C")
    print("=" * 60 + "\n", flush=True)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (ValueError, AttributeError):
        pass
    while True:
        time.sleep(3)
        dead = [nm for nm, p, _ in procs if p.poll() is not None]
        if any(nm == "checksystem" for nm in dead):
            print("[fatal] checksystem died; stopping all.", flush=True)
            shutdown()
        if dead:
            print("[warn] exited: %s" % ", ".join(dead), flush=True)
            procs[:] = [(nm, p, lf) for (nm, p, lf) in procs if p.poll() is None]


if __name__ == "__main__":
    main()
