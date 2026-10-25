"""Persistent farm state v2 — SQLite, stdlib only, WAL mode.

One DB is the single source of truth for every loop (collectors, submitter,
attack-data, GUI). It survives Ctrl+C / crash / box reboot without losing or
re-submitting flags.

Flag state machine:
  QUEUED    stolen, valid, waiting to be submitted (next_try gates retries)
  INFLIGHT  handed to the submitter this pass (crash-safe: requeued on restart)
  ACCEPTED  jury said OK — counts for points, terminal
  REJECTED  jury said invalid / own / too-old / duplicate — terminal
  EXPIRED   TTL passed or max retries hit — terminal, never resubmitted

Tables: flags · events · targets · exploit_health · meta.
"""
import json
import os
import sqlite3
import threading
import time

QUEUED, INFLIGHT, ACCEPTED, REJECTED, EXPIRED = (
    "QUEUED", "INFLIGHT", "ACCEPTED", "REJECTED", "EXPIRED")
TERMINAL = (ACCEPTED, REJECTED, EXPIRED)

DB_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "farm_state.db")
_lock = threading.RLock()
_conn = None
_db_path = DB_DEFAULT

_TABLES = """
CREATE TABLE IF NOT EXISTS flags(
  flag     TEXT PRIMARY KEY,
  status   TEXT NOT NULL,
  service  TEXT,
  target   TEXT,
  flag_id  TEXT,
  source   TEXT,
  tries    INTEGER DEFAULT 0,
  first    REAL,
  last     REAL,
  next_try REAL DEFAULT 0,
  verdict  TEXT
);
CREATE TABLE IF NOT EXISTS events(
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  ts    REAL, level TEXT, kind TEXT, msg TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS targets(
  name TEXT PRIMARY KEY, host TEXT,
  up INTEGER DEFAULT 1, last_seen REAL, cooldown_until REAL DEFAULT 0,
  stolen INTEGER DEFAULT 0, accepted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS exploit_health(
  service TEXT PRIMARY KEY,
  enabled INTEGER DEFAULT 1,
  runs INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
  last_ok REAL, last_err TEXT, avg_ms REAL DEFAULT 0,
  quarantined_until REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS ix_flags_claim  ON flags(status, next_try);
CREATE INDEX IF NOT EXISTS ix_flags_svc    ON flags(service, target);
CREATE INDEX IF NOT EXISTS ix_flags_accept ON flags(status, last);
CREATE INDEX IF NOT EXISTS ix_events_id    ON events(id);
"""

# columns added since v1 -> migrated in place on an existing DB
_FLAGS_COLS = {"flag_id": "TEXT", "source": "TEXT", "next_try": "REAL DEFAULT 0", "verdict": "TEXT"}
_STATUS_MAP = {"pending": QUEUED, "accepted": ACCEPTED, "dropped": REJECTED}


def _migrate():
    """Bring a pre-existing (v1) flags table up to the v2 schema without data loss."""
    cols = {r[1] for r in _conn.execute("PRAGMA table_info(flags)").fetchall()}
    if not cols:
        return  # fresh DB: CREATE TABLE already made the v2 schema
    for name, decl in _FLAGS_COLS.items():
        if name not in cols:
            _conn.execute("ALTER TABLE flags ADD COLUMN %s %s" % (name, decl))
    for old, new in _STATUS_MAP.items():
        _conn.execute("UPDATE flags SET status=? WHERE status=?", (new, old))


def init(path=None):
    """Open (or create) the DB, enable WAL, migrate v1 schema, recover crash state."""
    global _conn, _db_path
    _db_path = path or DB_DEFAULT
    _conn = sqlite3.connect(_db_path, check_same_thread=False, timeout=30)
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript(_TABLES)
        _migrate()
        _conn.executescript(_INDEXES)
        # crash recovery: flags left INFLIGHT by a killed submitter go back to QUEUED.
        _conn.execute("UPDATE flags SET status=? WHERE status=?", (QUEUED, INFLIGHT))
        _conn.commit()


def _now():
    return time.time()


# ----------------------------------------------------------------- flags ----
def add_flags(items):
    """items: iterable of (flag, service, target, flag_id, source).
    Insert new QUEUED flags; ignore ones we've already seen. Returns the list
    of flags that were genuinely new (for counting / attribution)."""
    new = []
    now = _now()
    with _lock:
        for flag, service, target, flag_id, source in items:
            cur = _conn.execute(
                "INSERT OR IGNORE INTO flags(flag,status,service,target,flag_id,source,"
                "first,last,next_try) VALUES(?,?,?,?,?,?,?,?,0)",
                (flag, QUEUED, service, target, (None if flag_id is None else str(flag_id)),
                 source, now, now))
            if cur.rowcount == 1:
                new.append(flag)
        _conn.commit()
    return new


def claim_for_submit(limit, order="newest_first"):
    """Atomically take up to `limit` ready flags and mark them INFLIGHT."""
    now = _now()
    order_sql = "first DESC" if order == "newest_first" else "first ASC"
    with _lock:
        rows = _conn.execute(
            "SELECT flag FROM flags WHERE status=? AND next_try<=? ORDER BY " + order_sql +
            " LIMIT ?", (QUEUED, now, int(limit))).fetchall()
        flags = [r["flag"] for r in rows]
        if flags:
            qs = ",".join("?" * len(flags))
            _conn.execute("UPDATE flags SET status=?, last=? WHERE flag IN (%s)" % qs,
                          [INFLIGHT, now] + flags)
            _conn.commit()
    return flags


def get_flag(flag):
    with _lock:
        r = _conn.execute("SELECT * FROM flags WHERE flag=?", (flag,)).fetchone()
    return dict(r) if r else None


def set_status(flag, status, next_try=None, verdict=None, inc_tries=False):
    sets = ["status=?", "last=?"]
    vals = [status, _now()]
    if next_try is not None:
        sets.append("next_try=?"); vals.append(next_try)
    if verdict is not None:
        sets.append("verdict=?"); vals.append(verdict[:200])
    if inc_tries:
        sets.append("tries=tries+1")
    vals.append(flag)
    with _lock:
        _conn.execute("UPDATE flags SET %s WHERE flag=?" % ",".join(sets), vals)
        _conn.commit()


def expire_stale(ttl, max_tries):
    """Mark QUEUED/INFLIGHT flags that are too old or retried too much EXPIRED."""
    now = _now()
    with _lock:
        cur = _conn.execute(
            "UPDATE flags SET status=?, last=? WHERE status IN (?,?) AND (first < ? OR tries > ?)",
            (EXPIRED, now, QUEUED, INFLIGHT, now - ttl, max_tries))
        _conn.commit()
        return cur.rowcount


def requeue_inflight():
    with _lock:
        _conn.execute("UPDATE flags SET status=? WHERE status=?", (QUEUED, INFLIGHT))
        _conn.commit()


# --------------------------------------------------------------- metrics ----
def stats():
    with _lock:
        rows = _conn.execute("SELECT status, COUNT(*) c FROM flags GROUP BY status").fetchall()
    return {r["status"]: r["c"] for r in rows}


def summary():
    """Everything the dashboard header/KPIs need in one call."""
    with _lock:
        by_status = {r["status"]: r["c"] for r in _conn.execute(
            "SELECT status, COUNT(*) c FROM flags GROUP BY status").fetchall()}
        per_svc = [dict(r) for r in _conn.execute(
            "SELECT service, "
            "SUM(1) total, "
            "SUM(status='ACCEPTED') accepted, "
            "SUM(status='QUEUED') queued, "
            "SUM(status='REJECTED') rejected, "
            "SUM(status='EXPIRED') expired "
            "FROM flags GROUP BY service").fetchall()]
        oldest = _conn.execute(
            "SELECT MIN(first) m FROM flags WHERE status=?", (QUEUED,)).fetchone()["m"]
        verdicts = {r["verdict"]: r["c"] for r in _conn.execute(
            "SELECT verdict, COUNT(*) c FROM flags WHERE verdict IS NOT NULL "
            "GROUP BY verdict").fetchall()}
    return {"by_status": by_status, "per_service": per_svc,
            "queue_oldest_age": (_now() - oldest) if oldest else 0, "verdicts": verdicts}


def accepted_timeseries(bucket=30, span=1800):
    """Accepted-flag counts bucketed over the last `span` seconds (for the chart)."""
    now = _now()
    start = now - span
    with _lock:
        rows = _conn.execute(
            "SELECT last FROM flags WHERE status=? AND last>=?", (ACCEPTED, start)).fetchall()
    buckets = {}
    for r in rows:
        b = int((r["last"] - start) // bucket)
        buckets[b] = buckets.get(b, 0) + 1
    n = int(span // bucket)
    return [buckets.get(i, 0) for i in range(n)]


def list_flags(status=None, service=None, target=None, q=None, limit=300):
    sql = "SELECT flag,status,service,target,flag_id,tries,first,last,verdict FROM flags WHERE 1=1"
    args = []
    if status:
        sql += " AND status=?"; args.append(status)
    if service:
        sql += " AND service=?"; args.append(service)
    if target:
        sql += " AND target=?"; args.append(target)
    if q:
        sql += " AND (flag LIKE ? OR service LIKE ? OR target LIKE ?)"
        args += ["%" + q + "%"] * 3
    sql += " ORDER BY last DESC LIMIT ?"; args.append(int(limit))
    with _lock:
        return [dict(r) for r in _conn.execute(sql, args).fetchall()]


# ---------------------------------------------------------------- events ----
def log_event(level, kind, msg, data=None):
    with _lock:
        _conn.execute("INSERT INTO events(ts,level,kind,msg,data) VALUES(?,?,?,?,?)",
                      (_now(), level, kind, msg, json.dumps(data) if data is not None else None))
        # keep the feed bounded so the DB never balloons during a long game
        _conn.execute("DELETE FROM events WHERE id < (SELECT MAX(id)-3000 FROM events)")
        _conn.commit()


def recent_events(limit=200, since_id=0):
    with _lock:
        rows = _conn.execute(
            "SELECT id,ts,level,kind,msg,data FROM events WHERE id>? ORDER BY id DESC LIMIT ?",
            (since_id, int(limit))).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------- targets ----
def upsert_target(name, host):
    with _lock:
        _conn.execute("INSERT OR IGNORE INTO targets(name,host,last_seen) VALUES(?,?,?)",
                      (name, host, _now()))
        _conn.execute("UPDATE targets SET host=? WHERE name=?", (host, name))
        _conn.commit()


def set_target_health(name, up, cooldown_until=None):
    sets = ["up=?", "last_seen=?"]
    vals = [1 if up else 0, _now()]
    if cooldown_until is not None:
        sets.append("cooldown_until=?"); vals.append(cooldown_until)
    vals.append(name)
    with _lock:
        _conn.execute("UPDATE targets SET %s WHERE name=?" % ",".join(sets), vals)
        _conn.commit()


def bump_target(name, stolen=0, accepted=0):
    with _lock:
        _conn.execute("UPDATE targets SET stolen=stolen+?, accepted=accepted+? WHERE name=?",
                      (stolen, accepted, name))
        _conn.commit()


def get_targets():
    with _lock:
        return [dict(r) for r in _conn.execute(
            "SELECT * FROM targets ORDER BY name").fetchall()]


def target_cooldown(name):
    with _lock:
        r = _conn.execute("SELECT cooldown_until FROM targets WHERE name=?", (name,)).fetchone()
    return r["cooldown_until"] if r else 0


# -------------------------------------------------------- exploit health ----
def ensure_exploit(service):
    with _lock:
        _conn.execute("INSERT OR IGNORE INTO exploit_health(service) VALUES(?)", (service,))
        _conn.commit()


def record_exploit_run(service, ok, ms, err=None):
    with _lock:
        r = _conn.execute("SELECT runs,avg_ms FROM exploit_health WHERE service=?",
                          (service,)).fetchone()
        runs = (r["runs"] if r else 0) + 1
        avg = (r["avg_ms"] if r and r["avg_ms"] else 0.0)
        avg = avg + (ms - avg) / runs  # running mean
        if ok:
            _conn.execute("UPDATE exploit_health SET runs=?,avg_ms=?,last_ok=? WHERE service=?",
                          (runs, avg, _now(), service))
        else:
            _conn.execute("UPDATE exploit_health SET runs=?,avg_ms=?,errors=errors+1,"
                          "last_err=? WHERE service=?", (runs, avg, (err or "")[:200], service))
        _conn.commit()


def set_quarantine(service, until):
    with _lock:
        _conn.execute("UPDATE exploit_health SET quarantined_until=? WHERE service=?",
                      (until, service))
        _conn.commit()


def set_exploit_enabled(service, enabled):
    with _lock:
        _conn.execute("INSERT OR IGNORE INTO exploit_health(service) VALUES(?)", (service,))
        _conn.execute("UPDATE exploit_health SET enabled=? WHERE service=?",
                      (1 if enabled else 0, service))
        _conn.commit()


def get_exploits():
    with _lock:
        return {r["service"]: dict(r) for r in _conn.execute(
            "SELECT * FROM exploit_health").fetchall()}


# ------------------------------------------------------------------ meta ----
def meta_get(key, default=None):
    with _lock:
        r = _conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if not r:
        return default
    try:
        return json.loads(r["value"])
    except Exception:
        return default


def meta_set(key, value):
    with _lock:
        _conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                      (key, json.dumps(value)))
        _conn.commit()
