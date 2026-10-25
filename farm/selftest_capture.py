#!/usr/bin/env python3
"""End-to-end self-test for the flag-capture pipeline (steal -> submit -> ACCEPTED).

Why this exists
---------------
The three training services committed to this repo are PATCHED (the defense half
of the exercise), so the reference exploits in farm/sploits/ correctly steal
NOTHING from them. That is the right outcome for defense, but it means the farm
cannot be smoke-tested against the committed tree -- a green "0 flags" run looks
identical whether the farm works or is completely broken.

This self-test closes that gap. It reconstructs the *vulnerable baseline* of the
three services from git history into a throwaway temp dir, boots a small range +
the checksystem, runs `farm.py --once` through the real pipeline, and asserts the
farm steals flags, submits them, and the jury marks them ACCEPTED. It also checks
the scoreboard registered the attack points.

It touches nothing tracked and tears everything down on exit.

    python farm/selftest_capture.py                 # 4 teams (3 enemies), fast tick
    python farm/selftest_capture.py --teams 3
    python farm/selftest_capture.py --keep          # leave temp dir for debugging

Exit codes:  0 = pipeline verified   1 = failure   77 = skipped
Skips (77) when a dependency is missing (flask / requests / pycryptodome) or when
no vulnerable baseline can be found in git history -- so it is CI-safe.

Needs the per-team service ports free: web 9300+i, crypto 9400+i, depot 9500+i,
plus one scoreboard port (auto-picked). Requires a git checkout (reads history).
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SVC_BASES = {"web": 9300, "crypto": 9400, "depot": 9500}
SECRET = "selftest-secret-do-not-use-in-prod"
MY_TEAM = "team1"
# A positive signature of each service's planted vulnerability, so we can pick a
# baseline commit that still has them (robust to history edits / new SHAs).
VULN_SIGNATURES = {
    "web": "user_id=%d",            # %-formatted SQL (vs. patched "user_id=?")
    "crypto": 'NONCE = b"\\x00"',   # fixed CTR nonce reused across items
}


def log(msg):
    print("[selftest] %s" % msg, flush=True)


def skip(msg):
    log("SKIP: %s" % msg)
    sys.exit(77)


def git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def port_open(port, host="127.0.0.1"):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def get_json(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def find_vulnerable_baseline():
    """Newest commit whose web/app.py still has the vulnerable %-format SQL.

    At that commit crypto + depot are at their baseline (vulnerable) too, since
    all three were patched together afterwards. Returns a commit-ish or None.
    """
    res = git("log", "--format=%H", "--", "services/web/app.py")
    if res.returncode != 0:
        return None
    for sha in res.stdout.split():
        content = git("show", "%s:services/web/app.py" % sha).stdout
        if VULN_SIGNATURES["web"] in content:
            return sha
    return None


def stage_vulnerable_services(baseline, dest):
    """Copy the current service dirs (checkers, aescipher, ...) then overwrite the
    three app.py with their vulnerable baseline versions."""
    os.makedirs(dest, exist_ok=True)
    for svc in SVC_BASES:
        src = os.path.join(REPO, "services", svc)
        shutil.copytree(src, os.path.join(dest, svc), dirs_exist_ok=True)
        vuln_app = git("show", "%s:services/%s/app.py" % (baseline, svc)).stdout
        if not vuln_app.strip():
            return False
        with open(os.path.join(dest, svc, "app.py"), "w", encoding="utf-8") as f:
            f.write(vuln_app)
    # sanity: the signatures we can assert positively must be present
    for svc, sig in VULN_SIGNATURES.items():
        with open(os.path.join(dest, svc, "app.py"), encoding="utf-8") as f:
            if sig not in f.read():
                return False
    return True


def write_test_config(path, db, port, ids, token):
    """A farm config that reuses the repo's farm/config.py and overrides only the
    endpoints/db/targets so the real pipeline runs against our temp range."""
    base_cfg = os.path.join(HERE, "config.py")
    content = '''import importlib.util, os
_spec = importlib.util.spec_from_file_location("base_cfg", {base!r})
_m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_m)
CONFIG = dict(_m.CONFIG)
CONFIG["db"] = {db!r}
CONFIG["targets"] = dict(CONFIG["targets"]); CONFIG["targets"]["ids"] = {ids!r}
CONFIG["attackdata"] = dict(CONFIG["attackdata"])
CONFIG["attackdata"]["url"] = "http://127.0.0.1:{port}/api/flag_ids"
CONFIG["submitter"] = dict(CONFIG["submitter"])
CONFIG["submitter"]["url"] = "http://127.0.0.1:{port}/flags"
CONFIG["submitter"]["token"] = {token!r}
CONFIG["gui"] = dict(CONFIG["gui"]); CONFIG["gui"]["enabled"] = False
resolve_address = _m.resolve_address
'''.format(base=base_cfg, db=db, ids=ids, port=port, token=token)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--teams", type=int, default=4, help="total teams (team1 = us)")
    ap.add_argument("--tick", type=int, default=6, help="checker tick seconds")
    ap.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = ap.parse_args()

    # flask: the services + checksystem; requests: the web/crypto exploit clients.
    # (The crypto service ships a self-contained pure-Python AES, so no pycryptodome.)
    for mod in ("flask", "requests"):
        try:
            __import__(mod)
        except Exception:
            skip("missing dependency %r (needed to boot the training range)" % mod)

    if not os.path.isdir(os.path.join(REPO, ".git")):
        skip("not a git checkout; cannot reconstruct the vulnerable baseline")
    baseline = find_vulnerable_baseline()
    if not baseline:
        skip("no vulnerable baseline found in history (services never had planted vulns?)")
    log("vulnerable baseline: %s" % baseline[:12])

    n = max(2, args.teams)
    port = free_port()
    for base in SVC_BASES.values():
        for i in range(1, n + 1):
            if port_open(base + i):
                skip("service port %d already in use (another range running?)" % (base + i))

    tmp = tempfile.mkdtemp(prefix="farm-selftest-")
    procs = []  # (name, Popen, logfile)

    def spawn(name, argv, cwd, env_extra):
        env = dict(os.environ)
        env.update(env_extra)
        lf = open(os.path.join(tmp, "%s.log" % name), "w")
        procs.append((name, subprocess.Popen(argv, cwd=cwd, env=env,
                                              stdout=lf, stderr=subprocess.STDOUT), lf))

    def teardown():
        for _n, p, _lf in procs:
            try:
                p.terminate()
            except Exception:
                pass
        t0 = time.time()
        for _n, p, _lf in procs:
            try:
                p.wait(timeout=max(0.1, 3 - (time.time() - t0)))
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        for _n, _p, lf in procs:
            try:
                lf.close()
            except Exception:
                pass
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            log("kept temp dir: %s" % tmp)

    signal.signal(signal.SIGINT, lambda *_: (teardown(), sys.exit(1)))
    rc = 1
    try:
        svcdir = os.path.join(tmp, "services")
        if not stage_vulnerable_services(baseline, svcdir):
            skip("could not stage a complete vulnerable baseline")

        # boot the vulnerable range
        for i in range(1, n + 1):
            for svc, base in SVC_BASES.items():
                cwd = os.path.join(tmp, "run", "team%d" % i, svc)
                os.makedirs(cwd, exist_ok=True)
                spawn("team%d-%s" % (i, svc),
                      [sys.executable, os.path.join(svcdir, svc, "app.py")],
                      cwd, {"PORT": str(base + i)})
        teams_json = json.dumps([
            {"name": "team%d" % i, "host": "127.0.0.1",
             "ports": {s: b + i for s, b in SVC_BASES.items()}}
            for i in range(1, n + 1)
        ])
        spawn("checksystem", [sys.executable, "app.py"],
              os.path.join(REPO, "infra", "checksystem"),
              {"TEAMS_JSON": teams_json, "SERVICES_DIR": svcdir,
               "DATA_DIR": os.path.join(tmp, "cs"), "SCOREBOARD_PORT": str(port),
               "GAME_SECRET": SECRET, "MY_TEAM": MY_TEAM,
               "TICK_SECONDS": str(args.tick), "FLAG_LIFETIME_TICKS": "10"})

        base_url = "http://127.0.0.1:%d" % port
        t0 = time.time()
        while time.time() - t0 < 40:
            try:
                get_json(base_url + "/api/health")
                break
            except Exception:
                time.sleep(1)
        else:
            log("FAIL: scoreboard did not come up (see %s/checksystem.log)" % tmp)
            return rc

        # wait for the first flags to be planted
        t0 = time.time()
        planted = False
        while time.time() - t0 < max(20, args.tick * 3):
            fi = get_json(base_url + "/api/flag_ids")
            if any(ids for sv in fi["flag_ids"].values() for ids in sv.values()):
                planted = True
                break
            time.sleep(1)
        if not planted:
            log("FAIL: no flags were planted")
            return rc
        log("flags planted at tick %s" % fi["tick"])

        token = hmac.new(SECRET.encode(), MY_TEAM.encode(), hashlib.sha256).hexdigest()[:16]
        cfg = os.path.join(tmp, "config_selftest.py")
        write_test_config(cfg, os.path.join(tmp, "farm.db"), port,
                          list(range(1, n + 1)), token)

        out = subprocess.run(
            [sys.executable, os.path.join(HERE, "farm.py"),
             "--config", cfg, "--once", "--no-gui"],
            cwd=REPO, capture_output=True, text=True, timeout=120)
        tail = "\n".join(out.stdout.splitlines()[-6:])
        log("farm output tail:\n%s" % tail)

        m = re.search(r"'accepted':\s*(\d+)", out.stdout)
        accepted = int(m.group(1)) if m else 0
        board = get_json(base_url + "/api/scoreboard")
        me = next((r for r in board["teams"] if r.get("is_me")), {})
        attack = me.get("attack", 0)
        log("accepted=%d  scoreboard team1 attack=%s" % (accepted, attack))

        if accepted > 0 and attack and attack > 0:
            log("PASS: steal -> submit -> ACCEPTED verified (%d flags)" % accepted)
            rc = 0
        else:
            log("FAIL: expected accepted>0 and scoreboard attack>0")
        return rc
    finally:
        teardown()


if __name__ == "__main__":
    sys.exit(main())
