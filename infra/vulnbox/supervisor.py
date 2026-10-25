"""Runs all three vulnerable services inside one team vulnbox container.

Each service is started as a child process with its own PORT and its own
working directory (so their ./data dirs don't collide). If any service dies,
the whole container exits so Docker restarts it.
"""
import os
import sys
import time
import signal
import subprocess

SERVICES = [("web", 5001), ("crypto", 5002), ("depot", 5003)]
BASE = "/app/services"

procs = []


def start_all():
    for name, port in SERVICES:
        cwd = os.path.join(BASE, name)
        env = os.environ.copy()
        env["PORT"] = str(port)
        print("[vulnbox] starting %s on :%d" % (name, port), flush=True)
        procs.append((name, subprocess.Popen([sys.executable, "app.py"], cwd=cwd, env=env)))


def shutdown(*_):
    for name, p in procs:
        if p.poll() is None:
            p.terminate()
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    start_all()
    while True:
        for name, p in procs:
            rc = p.poll()
            if rc is not None:
                print("[vulnbox] service '%s' exited (rc=%s); shutting down" % (name, rc), flush=True)
                shutdown()
        time.sleep(1)


if __name__ == "__main__":
    main()
