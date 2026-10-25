"""Backward-compat shim for v1. New code uses engine.Engine.

One round = collectors.run_round (steal + queue) + submitter.drain_once (submit).
Kept so any older script doing `import runner; runner.run_once(cfg, log)` still works.
"""
import collectors
import runtime
import store
import submitter


def run_once(cfg, log, only_service=None, only_team=None, dry=False):
    if store._conn is None:
        store.init(cfg.get("db"))
    runtime.init(cfg)
    summ = collectors.run_round(cfg, log, only_service=only_service, only_team=only_team)
    if not dry:
        submitter.drain_once(cfg, log)
    return summ
