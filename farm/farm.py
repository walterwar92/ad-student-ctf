#!/usr/bin/env python3
"""A&D attack farm v2 — decoupled, self-tuning, observable. Stdlib only.

    python farm/farm.py --loop                      # steal + submit forever, with GUI
    python farm/farm.py --once                       # one round, drain queue, exit
    python farm/farm.py --once --dry-run             # steal + queue, DON'T submit (safe test)
    python farm/farm.py --loop --service web         # only one service
    python farm/farm.py --once --team team3          # only one target
    python farm/farm.py --loop --no-gui              # headless
    python farm/farm.py --config farm/config.forcad.py --loop

GUI: http://127.0.0.1:8070 (by default) — live stats + pause/enable/rate/reload controls.
Fill farm/config.py (or config.forcad.py) on test day. Drop one exploit per service into
farm/sploits/<service>.py exposing  exploit(host, port, flag_id) -> list[str].
"""
import argparse
import importlib.util
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # so `import store` etc. works

import store          # noqa: E402
import runtime        # noqa: E402
from engine import Engine  # noqa: E402
from util import get_logger  # noqa: E402


def load_config(path):
    spec = importlib.util.spec_from_file_location("farm_config", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cfg = dict(m.CONFIG)
    cfg["resolve_address"] = getattr(m, "resolve_address", None)
    cfg["extract_attackdata"] = getattr(m, "extract_attackdata", None)
    return cfg


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(here, "config.py"))
    ap.add_argument("--loop", action="store_true", help="run continuously")
    ap.add_argument("--once", action="store_true", help="single round then exit (default)")
    ap.add_argument("--round", type=int, default=None, help="override round seconds")
    ap.add_argument("--dry-run", action="store_true", help="steal + queue but do not submit")
    ap.add_argument("--service", help="only this service")
    ap.add_argument("--team", help="only this target, e.g. team3")
    ap.add_argument("--no-gui", action="store_true", help="headless (no dashboard)")
    ap.add_argument("--no-open", action="store_true", help="don't auto-open the dashboard in a browser")
    ap.add_argument("--gui-port", type=int, default=None)
    ap.add_argument("--gui-host", default=None)
    args = ap.parse_args()

    log = get_logger()
    cfg = load_config(args.config)
    if args.round:
        cfg["round_seconds"] = args.round
    gui = cfg.setdefault("gui", {})
    if args.gui_port:
        gui["port"] = args.gui_port
    if args.gui_host:
        gui["host"] = args.gui_host
    if args.no_gui:
        gui["enabled"] = False
    if args.no_open:
        gui["open_browser"] = False

    store.init(cfg.get("db"))
    runtime.init(cfg)

    eng = Engine(cfg, log, only_service=args.service, only_team=args.team, gui=not args.no_gui)

    if not args.loop:
        eng.run_once(dry=args.dry_run)
        return

    def on_stop(*_):
        eng.stop.set()
    signal.signal(signal.SIGINT, on_stop)
    try:
        signal.signal(signal.SIGTERM, on_stop)
    except (ValueError, AttributeError):
        pass

    eng.start()
    eng.wait()
    eng.shutdown()


if __name__ == "__main__":
    main()
