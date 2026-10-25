"""Dashboard + control API, stdlib http.server only. Bind 127.0.0.1 by default.

The frontend (dashboard.html) is a generic single-page app with neutral field
names; this server translates the farm's internals into that neutral wire shape,
so the UI can be edited standalone and dropped in unchanged.

GET  /                     the dashboard page (read from dashboard.html on disk)
GET  /api/settings         {refresh_ms, lock}
GET  /api/stats            header + tiles + chart + verdict buckets
GET  /api/list1            per-service health      (was: exploits)
GET  /api/list2            per-team state          (was: targets)
GET  /api/list3?s=&q=      flag rows               (was: flags)
GET  /api/log?since=       event feed
POST /api/action           {do: a1..a8, k, v, r, o}  (pause/resume/rate/toggles/reload/run)
POST /push                 team clients push stolen flags: {flags:[...],service,target,source}

Mutating endpoints (POST) require header X-Farm-Token when a token is configured.
"""
import json
import math
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import attackdata
import collectors
import runtime
import store
from webgui import assets

CHART_BUCKET = 30
CHART_SPAN = 1800

# neutral <-> farm vocabulary (keeps the frontend domain-agnostic)
_S2CODE = {"ACCEPTED": "s1", "QUEUED": "s2", "REJECTED": "s3", "EXPIRED": "s4", "INFLIGHT": "s5"}
_CODE2S = {v: k for k, v in _S2CODE.items()}
_O2CODE = {"newest_first": "o1", "oldest_first": "o2"}
_CODE2O = {v: k for k, v in _O2CODE.items()}


def make_server(cfg, log, engine_state):
    host = cfg.get("gui", {}).get("host", "127.0.0.1")
    port = int(cfg.get("gui", {}).get("port", 8070))
    token = cfg.get("gui", {}).get("token")
    poll = cfg.get("gui", {}).get("poll_ms", 1500)
    fre = re.compile(cfg["flag_regex"])

    def token_ok(handler):
        return (not token) or handler.headers.get("X-Farm-Token") == token

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # keep the game log clean

        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # -------------------------------------------------------- GET --
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/":
                    return self._send(200, assets.page(), "text/html; charset=utf-8")
                if u.path == "/api/settings":
                    return self._send(200, {"refresh_ms": poll, "lock": bool(token)})
                if u.path == "/api/stats":
                    return self._send(200, self._stats())
                if u.path == "/api/list1":
                    return self._send(200, self._list1())
                if u.path == "/api/list2":
                    return self._send(200, {"rows": self._list2()})
                if u.path == "/api/list3":
                    return self._send(200, {"rows": self._list3(q)})
                if u.path == "/api/log":
                    since = int(q.get("since", ["0"])[0] or 0)
                    evs = store.recent_events(200, since)
                    return self._send(200, {"rows": evs, "last": evs[0]["id"] if evs else since})
                return self._send(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": repr(e)})

        # ------------------------------------------------------- POST --
        def do_POST(self):
            u = urlparse(self.path)
            if not token_ok(self):
                return self._send(403, {"error": "bad token"})
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                body = {}
            try:
                if u.path == "/api/action":
                    return self._send(200, self._action(body))
                if u.path == "/push":
                    return self._send(200, self._push(body))
                return self._send(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001
                return self._send(500, {"error": repr(e)})

        # ------------------------------------------------- translators --
        def _stats(self):
            s = store.summary()
            bs = s["by_status"]
            ts = store.accepted_timeseries(CHART_BUCKET, CHART_SPAN)
            win = max(1, int(math.ceil(60 / CHART_BUCKET)))
            tok = cfg.get("submitter", {}).get("token", "") or ""
            mask = (tok[:3] + "…" + str(len(tok))) if tok else "none"
            vc = store.meta_get("verdict_counts", {})
            return {
                "s": runtime.get("paused"),
                "n1": engine_state.get("round", 0),
                "n2": time.time() - engine_state.get("started", time.time()),
                "n3": attackdata.age(),
                "r": runtime.get("flags_per_min"),
                "o": _O2CODE.get(runtime.get("order"), "o1"),
                "tag": mask,
                "series": ts, "bucket": CHART_BUCKET,
                "dist": {"accepted": vc.get("accepted", 0), "drop": vc.get("drop", 0),
                         "resubmit": vc.get("resubmit", 0), "unknown": vc.get("unknown", 0)},
                "m": {"m1": bs.get("ACCEPTED", 0), "m2": sum(ts[-win:]),
                      "m3": bs.get("QUEUED", 0), "m4": bs.get("REJECTED", 0),
                      "m5": bs.get("EXPIRED", 0),
                      "m6": engine_state.get("last_round", {}).get("stolen", 0)},
            }

        def _list1(self):
            rows = {}
            for svc, h in store.get_exploits().items():
                rows[svc] = {"on": h.get("enabled", 1), "a": h.get("runs", 0),
                             "b": h.get("errors", 0), "c": h.get("avg_ms", 0),
                             "q": h.get("quarantined_until", 0)}
            return {"rows": rows}

        def _list2(self):
            out = []
            for t in store.get_targets():
                out.append({"id": t["name"], "h": t.get("host", ""), "up": t.get("up", 1),
                            "seen": t.get("last_seen"), "cd": t.get("cooldown_until", 0),
                            "x": t.get("stolen", 0), "y": t.get("accepted", 0),
                            "off": not runtime.target_enabled(t["name"])})
            return out

        def _list3(self, q):
            scode = (q.get("s", [""])[0] or "")
            status = _CODE2S.get(scode)
            rows = store.list_flags(status=status, q=(q.get("q", [""])[0] or None))
            return [{"v": f["flag"], "s": _S2CODE.get(f["status"], "s2"),
                     "g": f.get("service"), "t": f.get("target"), "k": f.get("tries", 0),
                     "note": f.get("verdict"), "ts": f.get("first")} for f in rows]

        def _action(self, b):
            do = b.get("do")
            k, v = b.get("k"), b.get("v")
            if do == "a1":
                runtime.set("paused", True)
            elif do == "a2":
                runtime.set("paused", False)
                runtime.set("submit_backoff_until", 0)
            elif do == "a3":
                if b.get("r"):
                    runtime.set("flags_per_min", float(b["r"]))
                if b.get("o"):
                    runtime.set("order", _CODE2O.get(b["o"], runtime.get("order")))
            elif do == "a4":
                runtime.set_service_enabled(k, bool(v))
            elif do == "a5":
                store.set_exploit_enabled(k, bool(v))
                if v:
                    store.set_quarantine(k, 0)
            elif do == "a6":
                runtime.set_target_enabled(k, bool(v))
            elif do == "a7":
                collectors.reload_service(k)
            elif do == "a8":
                threading.Thread(target=self._run_now, args=(k,), daemon=True).start()
            else:
                return {"error": "unknown action %r" % do}
            store.log_event("INFO", "control", "%s %s" % (do, {x: y for x, y in b.items() if x != "do"}))
            return {"ok": True}

        def _run_now(self, svc):
            try:
                collectors.run_round(cfg, log, only_service=svc or None, source="manual")
            except Exception as e:  # noqa: BLE001
                log.warning("run_now error: %r" % e)

        def _push(self, b):
            flags = b.get("flags") or []
            svc, tgt = b.get("service"), b.get("target")
            src = "push:" + str(b.get("source", "?"))
            recs = [(f.strip(), svc, tgt, None, src) for f in flags
                    if isinstance(f, str) and fre.fullmatch(f.strip())]
            new = store.add_flags(recs) if recs else []
            if new:
                store.log_event("INFO", "push", "+%d flag(s) from %s" % (len(new), src))
            return {"seen": len(flags), "queued": len(new)}

    httpd = ThreadingHTTPServer((host, port), Handler)
    log.info("GUI on http://%s:%d%s" % (host, port, "  (token required)" if token else ""))
    return httpd
