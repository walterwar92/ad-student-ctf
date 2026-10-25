"""Farm configuration.

As shipped it points at the LOCAL training range (run_local.py) so you can test
the farm immediately. On test day, change the marked blocks: targets, attack-data
URL, submitter + token. Everything is plain Python (no YAML dep), so you can even
put small functions here (resolve_address, extract_attackdata).
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG = {
    # ---- game timing ----
    "round_seconds": 30,                    # how often --loop farms; align to the tick
    "flag_regex": r"[A-Z0-9]{31}=",         # <-- set to the organizers' flag format

    # ---- who you are / who to hit ----
    "my_team_id": 1,                        # never attack yourself
    "targets": {
        "mode": "template",                 # template | list | from_attackdata
        "name_template": "team%d",
        "ids": list(range(1, 11)),          # team ids to attack (your id is skipped)
        # "list": {"team2": "10.60.2.2", "team3": "10.60.3.2"},   # for mode="list"
    },

    # ---- services -> port ----
    # LOCAL: base port; real address is computed in resolve_address() below.
    # REAL (fixed port per service, host varies by team): put the real ports here.
    "services": {"web": 9300, "crypto": 9400, "depot": 9500},

    # ---- exploits: one file per service exposing exploit(host, port, flag_id) ----
    # LOCAL reuses the range's reference exploits. On test day point these at
    # farm/sploits/<service>.py (your freshly written ones).
    "sploit_paths": {
        "web":    os.path.join(REPO, "services", "web", "sploit.py"),
        "crypto": os.path.join(REPO, "services", "crypto", "sploit.py"),
        "depot":  os.path.join(REPO, "services", "depot", "sploit.py"),
        # "web": os.path.join(REPO, "farm", "sploits", "web.py"),
    },

    # ---- attack data (public flag ids of attackable flags) ----
    "attackdata": {
        "mode": "http_json",                # http_json | none
        "url": "http://127.0.0.1:8090/api/flag_ids",
        "format": "teamservice",            # teamservice | forcad | custom
        "data_key": "flag_ids",             # for teamservice: where the map lives
        "poll_seconds": None,               # None -> use round_seconds
        # REAL ForcAD example:
        # "url": "http://10.60.0.1/api/client/attack_data/", "format": "forcad",
    },

    # ---- submitter ----
    "submitter": {
        "mode": "http",                     # http | tcp
        # --- HTTP submitter (this range) ---
        "url": "http://127.0.0.1:8090/flags",
        "method": "POST",
        "token_header": "X-Team-Token",
        "token": "170380a444e440aa",        # <-- your team's submit token
        "json_body": False,                 # True => send JSON array instead of newline text
        # --- TCP submitter (common on RuCTF/ForcAD; set mode="tcp") ---
        # "host": "10.60.0.1", "port": 31337,
        # "send_token_first": True, "token": "<YOUR_TOKEN>",
        # "greeting_lines": 1,              # lines to read/skip after connect
        # "token_reply_lines": 1,           # lines to read after sending the token
        # "batch": True,                    # send all flags then read (vs one-by-one)
        "timeout": 10,
        # ---- v2 submit pacing (all optional) ----
        "flags_per_min": 300,               # starting submit rate; autotune refines it
        "autotune": True,                   # AIMD: find the jury's real flags/min ceiling
        "order": "newest_first",            # newest_first | oldest_first
        "min_flags_per_min": 30,            # AIMD floor
        "max_flags_per_min": 1200,          # AIMD ceiling
        "global_backoff": 15,               # submit pause (s) on "game not started/paused"
    },

    # ---- how to read the submitter's per-flag verdict (regex over the response line) ----
    "verdicts": {
        "accepted": r"(?i)\bACCEPTED\b|accepted|\bYES\b|\bOK\b",
        "resubmit": r"(?i)queue|too fast|rate.?limit|nop team|try later|game (?:not|over)|not started",
        "drop":     r"(?i)OWN_FLAG|TOO_OLD|DUPLICATE|INVALID|NO_SUCH_FLAG|own|too old|expired|invalid|already|not found",
    },

    # ---- rate limits / concurrency ----
    "limits": {
        "flags_per_submit": 100,            # chunk size per submit call
        "min_seconds_between_submits": 0.3, # pause between chunks (respect jury limits)
        "exploit_timeout": 8,               # advisory; exploits MUST set their own socket timeouts
        "max_workers": 20,                  # concurrent exploit threads
    },

    # ---- v2: flag lifetime, retries, collectors, GUI (all optional) ----
    # TTL: a queued flag older than this is EXPIRED (not resubmitted). Local range:
    # FLAG_LIFETIME_TICKS(5) * TICK_SECONDS(30) = 150s.
    "flag_lifetime_seconds": 150,
    "retry": {"max_tries": 40, "backoff": [2, 5, 10, 30]},

    # ---- optional: override the default SQLite path (defaults to farm/farm_state.db) ----
    # "db": "/path/to/farm_state.db",

    "collectors": {
        "hard_timeout": 10,                 # forced cap on one exploit() call
        "isolation": "thread",              # thread | subprocess
        "subprocess_services": [],          # e.g. ["pwnny"] — run those exploits as killable procs
        "hot_reload": True,                 # pick up edited exploit files by mtime
        "quarantine": {"err_ratio": 0.9, "rounds": 3, "cooldown": 120},
        "target_cooldown": 60,              # skip an unreachable team for N s, then re-probe
        "local_enabled": True,              # steal here (False = pure submit server for the team)
    },

    "gui": {
        "enabled": True,
        "host": "127.0.0.1",                # localhost only; teammates: set to your VPN IP + token
        "port": 8070,
        "token": None,                      # set a string to require X-Farm-Token on POST/push
        "poll_ms": 1500,
        "open_browser": True,               # auto-open the dashboard on --loop (CLI: --no-open)
    },
}


def resolve_address(target, service, base_port):
    """Return (host, port) for a given team+service.

    LOCAL stand: one host, port = base + team id.
    REAL platform (fixed port, host per team): return (target['host'] or the ip
    template, base_port). Examples:
        return ("10.60.%d.2" % target["id"], base_port)     # template by id
        return (target["host"], base_port)                  # mode="list"/"from_attackdata"
    """
    return ("127.0.0.1", base_port + target["id"])          # <-- LOCAL; change on test day


# Optional: only needed when attackdata['format'] == 'custom'.
# def extract_attackdata(raw):
#     # raw = whatever the organizers' endpoint returns; return
#     # { team_key: { service: [flag_id, ...] } }
#     return {}
