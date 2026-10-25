"""Engine: owns the lifecycle and runs the decoupled loops as supervised threads.

  attack-data poller  — refresh the flag-id cache on its own cadence
  collectors loop     — steal flags every round (respects runtime toggles/quarantine)
  submitter loop      — drain the queue to the jury on its own schedule
  GUI server          — dashboard + control API

A crashing loop is logged as an ERROR event and restarted with backoff — the game
keeps running. State lives in SQLite, so a full process restart resumes cleanly.
"""
import threading
import time

import attackdata
import collectors
import runtime
import store
import submitter


class Engine:
    def __init__(self, cfg, log, only_service=None, only_team=None, gui=True):
        self.cfg = cfg
        self.log = log
        self.only_service = only_service
        self.only_team = only_team
        self.gui = gui
        self.stop = threading.Event()
        self.state = {"started": time.time(), "round": 0, "last_round": {}}
        self.httpd = None
        self.threads = []

    # ---------------------------------------------------------- loops --
    def _supervise(self, name, fn):
        def wrap():
            back = 1
            while not self.stop.is_set():
                try:
                    fn()
                    return  # clean return = loop saw stop
                except Exception as e:  # noqa: BLE001
                    self.log.error("%s crashed: %r (restart in %ss)" % (name, e, back))
                    store.log_event("ERROR", "engine", "%s crashed: %r" % (name, e))
                    self.stop.wait(back)
                    back = min(back * 2, 30)
        t = threading.Thread(target=wrap, name=name, daemon=True)
        t.start()
        self.threads.append(t)

    def _ad_loop(self):
        while not self.stop.is_set():
            attackdata.refresh(self.cfg, self.log)
            ps = self.cfg.get("attackdata", {}).get("poll_seconds") or runtime.get("round_seconds")
            self.stop.wait(max(3, int(ps or 15)))

    def _collect_loop(self):
        while not self.stop.is_set():
            t0 = time.time()
            if runtime.get("collectors_enabled"):
                summ = collectors.run_round(self.cfg, self.log,
                                            only_service=self.only_service,
                                            only_team=self.only_team)
                self.state["round"] += 1
                self.state["last_round"] = summ
            rs = max(2, int(runtime.get("round_seconds") or 30))
            self.stop.wait(max(0.0, rs - (time.time() - t0)))

    # ---------------------------------------------------------- modes --
    def start(self):
        store.requeue_inflight()
        self._supervise("attack-data", self._ad_loop)
        self._supervise("collectors", self._collect_loop)
        self._supervise("submitter",
                        lambda: submitter.run_loop(self.cfg, self.log, self.stop, dry=False))
        if self.gui and self.cfg.get("gui", {}).get("enabled", True):
            from webgui import server as guisrv
            self.httpd = guisrv.make_server(self.cfg, self.log, self.state)
            t = threading.Thread(target=self.httpd.serve_forever, name="gui", daemon=True)
            t.start()
            self.threads.append(t)
            self._maybe_open_browser()
        self.log.info("engine up: round=%ss rate=%s/min%s"
                      % (runtime.get("round_seconds"), runtime.get("flags_per_min"),
                         "" if runtime.get("collectors_enabled") else " [submit-only]"))

    def _maybe_open_browser(self):
        g = self.cfg.get("gui", {})
        if not g.get("open_browser", True):
            return
        host = g.get("host", "127.0.0.1")
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        url = "http://%s:%d" % (host, int(g.get("port", 8070)))
        try:
            import webbrowser
            webbrowser.open(url)
            self.log.info("opening dashboard in browser: %s" % url)
        except Exception as e:  # noqa: BLE001
            self.log.debug("auto-open browser failed: %r" % e)

    def wait(self):
        try:
            while not self.stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    def shutdown(self):
        self.log.info("stopping…")
        self.stop.set()
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
        self.log.info("done. store=%s" % store.stats())

    def run_once(self, dry=False):
        attackdata.refresh(self.cfg, self.log)
        store.requeue_inflight()
        summ = collectors.run_round(self.cfg, self.log,
                                    only_service=self.only_service, only_team=self.only_team)
        self.state["round"], self.state["last_round"] = 1, summ
        if dry:
            self.log.info("[dry-run] %d new flag(s) queued, NOT submitting" % summ.get("stolen", 0))
        else:
            submitter.drain_once(self.cfg, self.log)
        self.log.info("done. store=%s" % store.stats())
