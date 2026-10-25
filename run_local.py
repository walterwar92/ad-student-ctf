#!/usr/bin/env python3
"""Run the whole A&D range NATIVELY (no Docker), using the host's Python.

Use this when Docker Hub / PyPI are unreachable (as on this machine) or you just
want a fast, dependency-free run. Needs only Flask (already installed).

Each team gets its own working directory under run/teamN/<svc>/ (so their data
and flags stay isolated and team1 can be patched independently). Services listen
on 127.0.0.1 with the same port scheme Docker/attacker use:
    teamN:  web 9300+N, crypto 9400+N, depot 9500+N
    scoreboard: SCOREBOARD_PORT from .env (default 8090)

    python run_local.py                # TEAMS from .env (default 10)
    python run_local.py --teams 4       # lighter
    python run_local.py --fresh         # wipe run/ data first
Stop with Ctrl+C. Attack from another terminal: python attacker/attack.py --loop
"""
import argparse
import hashlib
import hmac
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SVC = [("web", 9300), ("crypto", 9400), ("depot", 9500)]
procs = []  # (name, Popen, logfile)


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
    for _n, p, lf in procs:
        try:
            lf.close()
        except Exception:
            pass
    sys.exit(0)


def main():
    env = read_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--teams", type=int, default=int(env.get("TEAMS", "10")))
    ap.add_argument("--fresh", action="store_true", help="wipe run/ data first")
    args = ap.parse_args()
    n = args.teams
    sbport = env.get("SCOREBOARD_PORT", "8090")

    rundir = os.path.join(ROOT, "run")
    if args.fresh and os.path.isdir(rundir):
        shutil.rmtree(rundir, ignore_errors=True)
    logdir = os.path.join(rundir, "_logs")
    os.makedirs(logdir, exist_ok=True)

    def spawn(name, argv, cwd, logname, envextra=None):
        e = dict(os.environ)
        if envextra:
            e.update(envextra)
        lf = open(os.path.join(logdir, logname), "w")
        p = subprocess.Popen(argv, cwd=cwd, env=e, stdout=lf, stderr=subprocess.STDOUT)
        procs.append((name, p, lf))

    print("Starting %d teams x 3 services + checksystem ..." % n)
    for i in range(1, n + 1):
        for svc, base in SVC:
            cwd = os.path.join(rundir, "team%d" % i, svc)
            os.makedirs(cwd, exist_ok=True)
            spawn("team%d-%s" % (i, svc),
                  [sys.executable, os.path.join(ROOT, "services", svc, "app.py")],
                  cwd, "team%d-%s.log" % (i, svc), {"PORT": str(base + i)})

    teams_json = json.dumps([
        {"name": "team%d" % i, "host": "127.0.0.1",
         "ports": {"web": 9300 + i, "crypto": 9400 + i, "depot": 9500 + i}}
        for i in range(1, n + 1)
    ])
    secret = env.get("GAME_SECRET", "studentctf-local-dev-change-me")
    my_team = env.get("MY_TEAM", "team1")
    spawn("checksystem", [sys.executable, "app.py"],
          os.path.join(ROOT, "infra", "checksystem"), "checksystem.log",
          {"TEAMS_JSON": teams_json,
           "SERVICES_DIR": os.path.join(ROOT, "services"),
           "DATA_DIR": os.path.join(rundir, "_checksystem"),
           "SCOREBOARD_PORT": sbport, "GAME_SECRET": secret, "MY_TEAM": my_team,
           "TICK_SECONDS": env.get("TICK_SECONDS", "30"),
           "FLAG_LIFETIME_TICKS": env.get("FLAG_LIFETIME_TICKS", "5")})

    up = wait_port(int(sbport))
    for svc, base in SVC:
        wait_port(base + 1)
    token = hmac.new(secret.encode(), my_team.encode(), hashlib.sha256).hexdigest()[:16]

    print("\n" + "=" * 60)
    print("  Scoreboard : http://127.0.0.1:%s   %s"
          % (sbport, "(up)" if up else "(NOT up -> run/_logs/checksystem.log)"))
    print("  Your team  : %s    submit-token: %s" % (my_team, token))
    print("  Targets    : team2..team%d" % n)
    print("               web 9301..930%d  crypto 9401..940%d  depot 9501..950%d"
          % (n % 10, n % 10, n % 10) if n < 10 else
          "               web 9301-9310  crypto 9401-9410  depot 9501-9510")
    print("  Attack     : python attacker/attack.py --loop")
    print("  Logs       : run/_logs/    |    Stop: Ctrl+C")
    print("=" * 60 + "\n")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    while True:
        time.sleep(3)
        dead = [n2 for n2, p, _ in procs if p.poll() is not None]
        if dead:
            print("[warn] exited: %s (see run/_logs/)" % ", ".join(dead))
            if any(n2 == "checksystem" for n2 in dead):
                print("[fatal] checksystem died; stopping all.")
                shutdown()
            procs[:] = [(n2, p, lf) for (n2, p, lf) in procs if p.poll() is None]


if __name__ == "__main__":
    main()
