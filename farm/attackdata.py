"""Fetch + cache the public 'attack data' (flag ids of attackable flags).

Normalises every source to:  { target_key : { service : [flag_id, ...] } }
where target_key is a team name or IP (whatever the source uses).

Presets (config['attackdata']['format']):
  teamservice : {"flag_ids": {"team2": {"web": [...]}}}   (local range format)
  forcad      : {"service": {"team_ip": [hint, ...]}}       (ForcAD platform)
  custom      : your own extract_attackdata(raw) in the config module

Robustness: the last SUCCESSFUL snapshot is cached. If a later fetch fails (jury
rebooting, endpoint 5xx, garbage/HTML), collectors keep attacking on the cached
data instead of attacking nobody. The cache age is surfaced in the GUI.
"""
import json
import threading
import time
import urllib.request

_lock = threading.Lock()
_cache = {"data": None, "ok_ts": None, "last_err": None}


def refresh(cfg, log=None):
    """Fetch + normalise; update the cache on success. Returns the fresh data, or
    the last-good cache on failure (or {} if we never succeeded)."""
    ad = cfg.get("attackdata", {})
    if ad.get("mode") != "http_json":
        return {}
    try:
        raw = _get_json(ad["url"], ad.get("timeout", 8))
        data = normalize(raw, ad.get("format", "teamservice"), ad, cfg, log)
        if not isinstance(data, dict):
            raise ValueError("normalized attack-data is not a mapping")
        with _lock:
            was_down = _cache["ok_ts"] is None or _cache["last_err"] is not None
            _cache["data"], _cache["ok_ts"], _cache["last_err"] = data, time.time(), None
        if was_down and log:
            log.info("attack-data OK: %d team(s)" % len(data))
        return data
    except Exception as e:
        with _lock:
            _cache["last_err"] = repr(e)
            cached = _cache["data"]
        if log:
            log.warning("attack-data fetch failed (%r); using cache age=%s" % (e, age()))
        return cached or {}


def snapshot():
    """(data, age_seconds_or_None, last_error_or_None) — read-only, for collectors/GUI."""
    with _lock:
        age_s = (time.time() - _cache["ok_ts"]) if _cache["ok_ts"] else None
        return (_cache["data"] or {}), age_s, _cache["last_err"]


def age():
    with _lock:
        return (time.time() - _cache["ok_ts"]) if _cache["ok_ts"] else None


# ----- fetch (back-compat shim for v1 callers) -----
def fetch(cfg, log=None):
    return refresh(cfg, log)


def normalize(raw, fmt, ad, cfg, log=None):
    if fmt == "teamservice":
        data = raw.get(ad.get("data_key", "flag_ids"), raw)
        return {k: {s: list(v) for s, v in sv.items()} for k, sv in data.items()}
    if fmt == "forcad":
        out = {}
        for svc, teams in raw.items():
            for team, items in teams.items():
                ids = []
                for it in items:
                    ids += _flatten(it)
                out.setdefault(team, {}).setdefault(svc, []).extend(ids)
        return out
    hook = cfg.get("extract_attackdata")
    if hook:
        return hook(raw)
    if log:
        log.warning("unknown attackdata format '%s' and no extract_attackdata hook" % fmt)
    return {}


def _flatten(it):
    if isinstance(it, str):
        return [it]
    if isinstance(it, (list, tuple)):
        r = []
        for x in it:
            r += _flatten(x)
        return r
    if isinstance(it, dict):
        r = []
        for x in it.values():
            r += _flatten(x)
        return r
    return [str(it)]


def _get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "ad-farm"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))
