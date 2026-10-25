"""Checksystem: background checker loop + scoreboard + flag submitter.

Plays the role of the organizers' infrastructure in an Attack & Defense CTF:
  * every TICK_SECONDS it plants a fresh flag into every service of every team,
    verifies the service works (SLA), and remembers the flag;
  * it exposes the PUBLIC flag ids of still-valid flags at /api/flag_ids;
  * teams submit stolen flags to POST /flags and earn attack points.
"""
import os
import re
import sys
import time
import threading
import importlib.util

from flask import Flask, request, jsonify, render_template, Response

import config
import checklib
import db

app = Flask(__name__)
FLAG_RE = re.compile(r"^[A-Z0-9]{31}=$")

CHECKERS = []  # list of (name, module, port)


def load_checkers():
    for name, defport in config.SERVICES:
        path = os.path.join(config.SERVICES_DIR, name, "checker.py")
        if not os.path.exists(path):
            print("[checksystem] WARNING: no checker at %s (service not built yet?)" % path, flush=True)
            continue
        spec = importlib.util.spec_from_file_location("checker_%s" % name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        port = getattr(mod, "DEFAULT_PORT", defport)
        CHECKERS.append((name, mod, port))
        print("[checksystem] loaded checker '%s' (port %d)" % (name, port), flush=True)


def _norm_put(r):
    if isinstance(r, (list, tuple)):
        if len(r) >= 3:
            return r[0], str(r[1]), str(r[2])
        if len(r) == 2:
            return r[0], str(r[1]), ""
    return r, "", ""


def tick_once(tick):
    for team in config.teams():
        for name, mod, defport in CHECKERS:
            # per-team port (native multi-team on one host) or the service default (Docker)
            port = (team.get("ports") or {}).get(name, defport)
            status = checklib.DOWN
            try:
                cs = mod.check(team["host"], port)
                flag = checklib.gen_flag()
                ps, fid, priv = _norm_put(mod.put(team["host"], port, flag))
                if ps == checklib.OK:
                    db.add_flag(team["name"], name, tick, flag, fid, priv,
                                tick + config.FLAG_LIFETIME_TICKS)
                gs = checklib.OK
                old = db.recent_flag(team["name"], name, max(tick - 1, 0))
                if old:
                    gs = mod.get(team["host"], port, old["flag_id"], old["flag"], old["private"])
                status = checklib.worst([cs, ps, gs])
            except Exception as e:  # noqa: BLE001 — a crashing checker must not kill the loop
                print("[checksystem] %s/%s error: %r" % (team["name"], name, e), flush=True)
                status = checklib.DOWN
            db.record_status(team["name"], name, tick, status)


def tick_loop():
    print("[checksystem] checker loop started (tick=%ds)" % config.TICK_SECONDS, flush=True)
    while True:
        tick = db.get_tick() + 1
        db.set_tick(tick)
        t0 = time.time()
        tick_once(tick)
        print("[checksystem] tick %d done in %.1fs" % (tick, time.time() - t0), flush=True)
        time.sleep(config.TICK_SECONDS)


# --------------------------------------------------------------------------- #
#  HTTP: scoreboard, flag ids, flag submission
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return jsonify(ok=True, tick=db.get_tick(), services=[c[0] for c in CHECKERS])


@app.get("/api/flag_ids")
def api_flag_ids():
    tick = db.get_tick()
    data = db.alive_flag_ids(tick)
    svc = request.args.get("service")
    team = request.args.get("team")
    if team:
        data = {team: data.get(team, {})}
    if svc:
        data = {t: {svc: v.get(svc, [])} for t, v in data.items()}
    return jsonify(tick=tick, flag_ids=data)


@app.get("/api/scoreboard")
def api_scoreboard():
    return jsonify(_board())


def _board():
    attack, lost, sla, svcstat = db.scoreboard()
    rows = []
    for t in config.teams():
        n = t["name"]
        a = attack.get(n, 0)
        s = round(sla.get(n, 0.0), 1)
        rows.append({
            "team": n,
            "is_me": n == config.MY_TEAM,
            "attack": a,
            "lost": lost.get(n, 0),
            "sla": s,
            "services": {name: svcstat.get(n, {}).get(name) for name, _m, _p in CHECKERS},
            "total": a * 10 + round(s),
        })
    rows.sort(key=lambda r: r["total"], reverse=True)
    return {"tick": db.get_tick(), "services": [c[0] for c in CHECKERS], "teams": rows}


@app.get("/")
def index():
    board = _board()
    return render_template("scoreboard.html",
                           board=board,
                           names=checklib.NAMES,
                           my_team=config.MY_TEAM)


@app.post("/flags")
def submit():
    token = request.headers.get("X-Team-Token", "")
    teams = {t["token"]: t["name"] for t in config.teams()}
    team_from = teams.get(token)
    if not team_from:
        return Response("ERR invalid team token\n", status=403, mimetype="text/plain")

    tick = db.get_tick()
    out = []
    for raw in request.get_data(as_text=True).splitlines():
        flag = raw.strip()
        if not flag:
            continue
        if not FLAG_RE.match(flag):
            out.append("%s INVALID" % flag)
            continue
        row = db.find_flag(flag)
        if row is None:
            out.append("%s NO_SUCH_FLAG" % flag)
            continue
        if row["alive_until"] < tick:
            out.append("%s TOO_OLD" % flag)
            continue
        if row["team"] == team_from:
            out.append("%s OWN_FLAG" % flag)
            continue
        if db.already_accepted(team_from, flag):
            out.append("%s DUPLICATE" % flag)
            continue
        db.record_accepted(team_from, flag, tick)
        out.append("%s ACCEPTED" % flag)
    return Response("\n".join(out) + "\n", mimetype="text/plain")


# Alias so both styles work.
app.add_url_rule("/api/submit", "submit_alias", submit, methods=["POST"])


def main():
    db.init()
    load_checkers()
    if not CHECKERS:
        print("[checksystem] no checkers loaded; is SERVICES_DIR correct? (%s)" % config.SERVICES_DIR,
              file=sys.stderr, flush=True)
    threading.Thread(target=tick_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=config.SCOREBOARD_PORT, threaded=True)


if __name__ == "__main__":
    main()
