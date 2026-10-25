"""Live, mutable runtime state — the knobs the GUI changes WITHOUT a restart.

Authority is an in-memory dict (fast, read every loop iteration); every change is
mirrored to store.meta['runtime'] so it survives a restart. Seeded from the config
file on first run, then owned by whatever the operator does in the dashboard.

Precedence:  runtime (GUI)  >  config.local/prod  >  config.py
"""
import threading
import time

import store

_lock = threading.RLock()
_state = {}

_DEFAULTS = {
    "paused": False,              # submitter paused (collectors keep stealing)
    "submit_backoff_until": 0.0,  # global submit pause (e.g. "game not started")
    "flags_per_min": 300.0,       # current submit rate (AIMD tunes this live)
    "order": "newest_first",      # newest_first | oldest_first
    "round_seconds": 30,
    "services_disabled": [],      # service names the operator turned off
    "targets_disabled": [],       # target names the operator turned off
    "collectors_enabled": True,   # run local exploits here (False = pure submit server)
}


def init(cfg):
    global _state
    saved = store.meta_get("runtime", None)
    base = dict(_DEFAULTS)
    # seed submit rate / order / round from the config file the first time
    sub = cfg.get("submitter", {})
    base["flags_per_min"] = float(sub.get("flags_per_min", base["flags_per_min"]))
    base["order"] = sub.get("order", base["order"])
    base["round_seconds"] = int(cfg.get("round_seconds", base["round_seconds"]))
    base["collectors_enabled"] = cfg.get("collectors", {}).get("local_enabled", True)
    if saved:
        base.update({k: v for k, v in saved.items() if k in _DEFAULTS})
    with _lock:
        _state = base
        _persist()


def _persist():
    store.meta_set("runtime", _state)


def get(key, default=None):
    with _lock:
        return _state.get(key, _DEFAULTS.get(key, default))


def snapshot():
    with _lock:
        return dict(_state)


def set(key, value):
    with _lock:
        _state[key] = value
        _persist()


def service_enabled(name):
    with _lock:
        return name not in _state.get("services_disabled", [])


def target_enabled(name):
    with _lock:
        return name not in _state.get("targets_disabled", [])


def _toggle(listkey, name, enabled):
    with _lock:
        lst = list(_state.get(listkey, []))
        if enabled and name in lst:
            lst.remove(name)
        elif not enabled and name not in lst:
            lst.append(name)
        _state[listkey] = lst
        _persist()


def set_service_enabled(name, enabled):
    _toggle("services_disabled", name, enabled)


def set_target_enabled(name, enabled):
    _toggle("targets_disabled", name, enabled)


def submit_allowed():
    """True when the submitter may send right now."""
    with _lock:
        if _state.get("paused"):
            return False
        return time.time() >= _state.get("submit_backoff_until", 0)


def backoff_submit(seconds):
    set("submit_backoff_until", time.time() + seconds)
