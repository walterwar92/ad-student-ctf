"""SQLite storage for the checksystem: planted flags, per-tick service status,
and accepted flag submissions."""
import os
import sqlite3
import threading

import config

_lock = threading.Lock()
_conn = None


def init():
    global _conn
    os.makedirs(config.DATA_DIR, exist_ok=True)
    _conn = sqlite3.connect(os.path.join(config.DATA_DIR, "checksystem.db"), check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flags(
          id INTEGER PRIMARY KEY,
          team TEXT, service TEXT, tick INTEGER,
          flag TEXT UNIQUE, flag_id TEXT, private TEXT, alive_until INTEGER);
        CREATE TABLE IF NOT EXISTS status(
          team TEXT, service TEXT, tick INTEGER, status INTEGER,
          PRIMARY KEY(team, service, tick));
        CREATE TABLE IF NOT EXISTS submissions(
          id INTEGER PRIMARY KEY,
          team_from TEXT, flag TEXT, verdict TEXT, tick INTEGER,
          UNIQUE(team_from, flag));
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE INDEX IF NOT EXISTS idx_flags_alive ON flags(alive_until);
        """
    )
    _conn.commit()


def get_tick():
    row = _conn.execute("SELECT value FROM meta WHERE key='tick'").fetchone()
    return int(row["value"]) if row else 0


def set_tick(t):
    with _lock:
        _conn.execute(
            "INSERT INTO meta(key,value) VALUES('tick',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(t),),
        )
        _conn.commit()


def add_flag(team, service, tick, flag, flag_id, private, alive_until):
    with _lock:
        _conn.execute(
            "INSERT OR IGNORE INTO flags(team,service,tick,flag,flag_id,private,alive_until) "
            "VALUES(?,?,?,?,?,?,?)",
            (team, service, tick, flag, flag_id, private, alive_until),
        )
        _conn.commit()


def recent_flag(team, service, tick):
    return _conn.execute(
        "SELECT * FROM flags WHERE team=? AND service=? AND tick=? LIMIT 1",
        (team, service, tick),
    ).fetchone()


def record_status(team, service, tick, status):
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO status(team,service,tick,status) VALUES(?,?,?,?)",
            (team, service, tick, status),
        )
        _conn.commit()


def alive_flag_ids(current_tick, limit_per=20):
    """Public: {team: {service: [flag_id, ...]}} for flags still submittable."""
    out = {}
    rows = _conn.execute(
        "SELECT team,service,flag_id FROM flags WHERE alive_until>=? ORDER BY id DESC",
        (current_tick,),
    ).fetchall()
    for r in rows:
        bucket = out.setdefault(r["team"], {}).setdefault(r["service"], [])
        if r["flag_id"] not in bucket and len(bucket) < limit_per:
            bucket.append(r["flag_id"])
    return out


def find_flag(flag):
    return _conn.execute("SELECT * FROM flags WHERE flag=?", (flag,)).fetchone()


def already_accepted(team_from, flag):
    return _conn.execute(
        "SELECT 1 FROM submissions WHERE team_from=? AND flag=? AND verdict='ACCEPTED'",
        (team_from, flag),
    ).fetchone() is not None


def record_accepted(team_from, flag, tick):
    with _lock:
        _conn.execute(
            "INSERT OR IGNORE INTO submissions(team_from,flag,verdict,tick) VALUES(?,?,'ACCEPTED',?)",
            (team_from, flag, tick),
        )
        _conn.commit()


def scoreboard():
    attack = {}
    for r in _conn.execute(
        "SELECT team_from, COUNT(*) c FROM submissions WHERE verdict='ACCEPTED' GROUP BY team_from"
    ).fetchall():
        attack[r["team_from"]] = r["c"]

    # flags lost (how many of a team's own flags were stolen by others)
    lost = {}
    for r in _conn.execute(
        "SELECT f.team t, COUNT(*) c FROM submissions s JOIN flags f ON f.flag=s.flag "
        "WHERE s.verdict='ACCEPTED' GROUP BY f.team"
    ).fetchall():
        lost[r["t"]] = r["c"]

    sla = {}
    for r in _conn.execute(
        "SELECT team, SUM(CASE WHEN status=101 THEN 1 ELSE 0 END) ok, COUNT(*) tot "
        "FROM status GROUP BY team"
    ).fetchall():
        sla[r["team"]] = (r["ok"] / r["tot"] * 100.0) if r["tot"] else 0.0

    svcstat = {}
    for r in _conn.execute(
        "SELECT team, service, status FROM status "
        "WHERE (team,service,tick) IN (SELECT team,service,MAX(tick) FROM status GROUP BY team,service)"
    ).fetchall():
        svcstat.setdefault(r["team"], {})[r["service"]] = r["status"]

    return attack, lost, sla, svcstat
