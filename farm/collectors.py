"""Collectors: run every exploit against every (team, service, flag_id) and queue
the stolen flags. Decoupled from submission — this only STEALS and persists.

Hardening over v1:
  * hard per-round time budget + per-exploit timeout (hung exploit can't drain the pool)
  * optional subprocess isolation per service (kill on timeout; survives segfault/leak)
  * hot-reload: an edited exploit file is picked up by mtime, no restart
  * quarantine: an exploit that fails every job for N rounds is benched (loudly) and
    periodically re-probed
  * target cooldown: an unreachable team is skipped for a while, then re-probed
"""
import concurrent.futures as cf
import importlib.util
import math
import os
import re
import subprocess
import sys
import threading
import time

import attackdata
import runtime
import store
import targets as targets_mod

_lock = threading.Lock()
_round_lock = threading.Lock()   # serialize scheduled rounds vs GUI "run now"
_sploits = {}            # svc -> {"mod":module, "mtime":float, "path":str}
_force_reload = set()    # svc names the GUI asked to reload
_svc_bad_rounds = {}     # svc -> consecutive all-failed rounds


def reload_service(svc):
    with _lock:
        _force_reload.add(svc)


def _get_sploit(svc, path, log):
    if not path or not os.path.exists(path):
        return None
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    with _lock:
        cached = _sploits.get(svc)
        force = svc in _force_reload
        if cached and not force and cached["mtime"] == mtime:
            return cached["mod"]
        _force_reload.discard(svc)
    try:
        spec = importlib.util.spec_from_file_location("sp_" + re.sub(r"\W", "_", path), path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        with _lock:
            _sploits[svc] = {"mod": m, "mtime": mtime, "path": path}
        if cached:
            log.info("reloaded exploit '%s'" % svc)
            store.log_event("INFO", "reload", "reloaded exploit %s" % svc)
        return m
    except Exception as e:
        log.warning("exploit load failed '%s' (%r)" % (svc, e))
        store.log_event("WARN", "reload", "exploit %s failed to load: %r" % (svc, e))
        return None


def _isolation_for(cfg, svc):
    col = cfg.get("collectors", {})
    if svc in col.get("subprocess_services", []):
        return "subprocess"
    return col.get("isolation", "thread")


def _run_thread(mod, host, port, fid):
    fl = mod.exploit(host, port, fid)
    return fl or []


def _run_subprocess(path, host, port, fid, hard_t, fre):
    argv = [sys.executable, path, str(host), str(port)]
    if fid is not None:
        argv.append(str(fid))
    p = subprocess.run(argv, capture_output=True, timeout=hard_t,
                        cwd=os.path.dirname(path) or None)
    out = (p.stdout or b"").decode("utf-8", "replace")
    return fre.findall(out)


def run_round(cfg, log, only_service=None, only_team=None, source="local"):
    with _round_lock:
        return _run_round(cfg, log, only_service, only_team, source)


def _run_round(cfg, log, only_service=None, only_team=None, source="local"):
    fre = re.compile(cfg["flag_regex"])
    col = cfg.get("collectors", {})
    hard_t = col.get("hard_timeout", cfg.get("limits", {}).get("exploit_timeout", 8) + 4)
    max_workers = cfg.get("limits", {}).get("max_workers", 20)
    quar = col.get("quarantine", {"err_ratio": 0.9, "rounds": 3, "cooldown": 120})
    tgt_cooldown = col.get("target_cooldown", 60)
    now = time.time()

    # --- attack data (refresh if we have nothing cached yet) ---
    data, ad_age, _ = attackdata.snapshot()
    if ad_age is None:
        data = attackdata.refresh(cfg, log)

    # --- resolve targets ---
    if cfg["targets"].get("mode") == "from_attackdata":
        excl = set(cfg["targets"].get("exclude_hosts", []))
        if cfg["targets"].get("my_team_ip"):
            excl.add(cfg["targets"]["my_team_ip"])
        tlist = [{"name": k, "host": k, "id": targets_mod._idof(k)}
                 for k in data.keys() if k not in excl]
    else:
        tlist = targets_mod.resolve(cfg)

    resolve_addr = cfg.get("resolve_address") or (lambda t, svc, base: (t.get("host"), base))
    exploits = store.get_exploits()

    # --- build jobs honoring runtime toggles / quarantine / cooldown ---
    jobs = []
    active_targets = []
    for t in tlist:
        if only_team and t["name"] != only_team:
            continue
        store.upsert_target(t["name"], t.get("host") or "")
        if not runtime.target_enabled(t["name"]):
            continue
        if store.target_cooldown(t["name"]) > now and not only_team:
            continue
        active_targets.append(t)
        entry = data.get(t["name"]) or data.get(t.get("host")) or data.get(str(t["id"])) or {}
        for svc, base in cfg["services"].items():
            if only_service and svc != only_service:
                continue
            if not runtime.service_enabled(svc):
                continue
            h = exploits.get(svc, {})
            if h and not h.get("enabled", 1):
                continue
            if h and h.get("quarantined_until", 0) > now and not only_service:
                continue
            path = cfg["sploit_paths"].get(svc)
            store.ensure_exploit(svc)
            if _isolation_for(cfg, svc) == "thread" and not _get_sploit(svc, path, log):
                continue
            if not path or not os.path.exists(path):
                continue
            host, port = resolve_addr(t, svc, base)
            fids = entry.get(svc) if entry else None
            if fids:
                for fid in fids:
                    jobs.append((t, svc, host, port, fid, path))
            else:
                jobs.append((t, svc, host, port, None, path))

    log.info("round: %d target(s), %d job(s)%s" % (
        len(active_targets), len(jobs),
        (" [attack-data age=%ds]" % int(ad_age)) if ad_age else ""))

    if not jobs:
        return {"targets": len(active_targets), "jobs": 0, "stolen": 0}

    # --- run jobs with a bounded round budget ---
    waves = math.ceil(len(jobs) / max(1, max_workers))
    budget = hard_t * waves + 3
    results = []  # (job, flags, err, ms)

    def run_one(job):
        t, svc, host, port, fid, path = job
        t0 = time.time()
        try:
            if _isolation_for(cfg, svc) == "subprocess":
                fl = _run_subprocess(path, host, port, fid, hard_t, fre)
            else:
                fl = _run_thread(_sploits[svc]["mod"], host, port, fid)
            return (job, fl, None, (time.time() - t0) * 1000)
        except subprocess.TimeoutExpired:
            return (job, None, "timeout", (time.time() - t0) * 1000)
        except Exception as e:  # noqa: BLE001
            return (job, None, repr(e), (time.time() - t0) * 1000)

    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(run_one, j): j for j in jobs}
        try:
            for fut in cf.as_completed(futs, timeout=budget):
                results.append(fut.result())
        except cf.TimeoutError:
            for fut, job in futs.items():
                if not fut.done():
                    results.append((job, None, "round-timeout", budget * 1000))

    # --- tally per service + per target, collect stolen flags ---
    records = []
    svc_total, svc_err = {}, {}
    for job, flags, err, ms in results:
        t, svc, host, port, fid, path = job
        svc_total[svc] = svc_total.get(svc, 0) + 1
        ok = err is None
        store.record_exploit_run(svc, ok, ms, err)
        if ok:
            for raw in flags:
                f = raw.strip() if isinstance(raw, str) else str(raw).strip()
                if fre.fullmatch(f):
                    records.append((f, svc, t["name"], fid, source))
        else:
            svc_err[svc] = svc_err.get(svc, 0) + 1
            log.debug("x %-10s %-12s id=%s -> %s" % (svc, t["name"], fid, err))

    # --- persist new flags (store dedups) ---
    new = store.add_flags(records) if records else []
    new_set = set(new)
    per_tgt_new = {}
    for f, svc, tname, fid, src in records:
        if f in new_set:
            per_tgt_new[tname] = per_tgt_new.get(tname, 0) + 1
            log.info("+ %-10s %-12s id=%-20s -> %s" % (svc, tname, str(fid), f))
    for tname, n in per_tgt_new.items():
        store.bump_target(tname, stolen=n)
    if new:
        store.log_event("INFO", "steal", "+%d new flag(s) from %s" % (len(new), source),
                        {"per_target": per_tgt_new})

    # --- target health: a target whose every job errored is down -> cooldown ---
    tgt_jobs, tgt_fail = {}, {}
    for job, flags, err, ms in results:
        nm = job[0]["name"]
        tgt_jobs[nm] = tgt_jobs.get(nm, 0) + 1
        if err is not None:
            tgt_fail[nm] = tgt_fail.get(nm, 0) + 1
    for nm, total in tgt_jobs.items():
        if total and tgt_fail.get(nm, 0) == total:
            store.set_target_health(nm, up=False, cooldown_until=now + tgt_cooldown)
        else:
            store.set_target_health(nm, up=True, cooldown_until=0)

    # --- quarantine exploits that fail a whole round, N rounds running ---
    for svc, total in svc_total.items():
        if only_service or only_team:
            continue
        bad = total > 0 and (svc_err.get(svc, 0) / total) >= quar.get("err_ratio", 0.9)
        if bad:
            _svc_bad_rounds[svc] = _svc_bad_rounds.get(svc, 0) + 1
            if _svc_bad_rounds[svc] >= quar.get("rounds", 3):
                store.set_quarantine(svc, now + quar.get("cooldown", 120))
                _svc_bad_rounds[svc] = 0
                log.warning("quarantined exploit '%s' (failing %d rounds)" % (svc, quar.get("rounds", 3)))
                store.log_event("WARN", "quarantine", "exploit %s quarantined" % svc)
        else:
            _svc_bad_rounds[svc] = 0

    return {"targets": len(active_targets), "jobs": len(jobs), "stolen": len(new)}
