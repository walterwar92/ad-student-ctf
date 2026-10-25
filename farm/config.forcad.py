"""Farm config pre-wired for the organizers' platform (ForcAD).

  Updated for the 2026 rules (Правила_26.pdf):
  platform    : ForcAD (github.com/pomo-mondreganto/ForcAD), VPN: WireGuard
  team boxes  : 10.60.N.2  (N = 1..10; first/last = 10.60.1.2 / 10.60.10.2)
  game server : http://10.10.10.10  (internal VPN HTTP interface)
                also reachable from the Internet over HTTPS at a GAME_HOST the
                organizers announce before start — then use https://GAME_HOST/...
  round       : 60 s   (rules: "Продолжительность раунда 1 минута")
  flag life   : 10 rounds = 600 s
  flag format : [A-Z0-9]{31}=
  attack data : GET  http://10.10.10.10/api/client/attack_data
                -> {"service_name": {"10.60.1.2": ["hint1","hint2"], ...}}  (hint == flag_id)
  submit flags: PUT  http://10.10.10.10/flags   (or https://GAME_HOST/flags)
                header X-Team-Token: <token>,  body = JSON array of flags

ON TEST DAY fill the 3 <<...>> below (your IP, your token, the services+ports),
then:  python farm/farm.py --config farm/config.forcad.py --once --dry-run
"""

CONFIG = {
    "round_seconds": 60,                       # 2026 rules: round = 1 minute
    "flag_regex": r"[A-Z0-9]{31}=",

    "targets": {
        "mode": "from_attackdata",             # attack exactly the teams the server lists
        "my_team_ip": "10.60.7.2",             # Prime = team 7 (pre-game audit); never attack it
        "exclude_hosts": [],                   # 2026: teams are 10.60.1.2..10.60.10.2, no nop team.
                                               # from_attackdata already skips my_team_ip above.
    },

    # service name (must match the task name in attack_data) -> port on the team box.
    # 2026 services, from the pre-game audit (ports are the public ones on 10.60.N.2).
    # A service with no sploit_paths entry (or a missing file) is simply skipped, so
    # vnek/StillAttached stay listed as reminders until their exploits are written.
    "services": {
        "muha": 8000,            # Flask/SQLite "ферма мух" — sploit READY
        "vnek": 28080,           # Go "вНеконтакте" — sploit READY (predictable UUIDv1 -> vault BOLA)
        "StillAttached": 18080,  # FastAPI web + pwn engine (engine:31337 internal) — TODO
    },

    # one exploit file per service (write the rest on the day from EXPLOIT_PROMPT_TEMPLATE.md).
    # Confirm each name matches the checker's task name in attack_data before relying on it.
    "sploit_paths": {
        "muha": "farm/sploits/muha.py",
        "vnek": "farm/sploits/vnek.py",
        # "StillAttached": "farm/sploits/stillattached.py",
    },

    "attackdata": {
        "mode": "http_json",
        # trailing slash is required: /api/client/attack_data 308-redirects to it,
        # and urllib does not reliably follow 308 (verified live on the game server).
        "url": "http://10.10.10.10/api/client/attack_data/",
        "format": "forcad",
        "poll_seconds": None,                  # None -> use round_seconds
    },

    "submitter": {
        "mode": "http",
        "url": "http://10.10.10.10/flags",
        "method": "PUT",
        "token_header": "X-Team-Token",
        "token": "<<YOUR_TEAM_TOKEN>>",
        "json_body": True,                     # ForcAD wants a JSON array
        "timeout": 10,
        # ---- v2 submit pacing ----
        "flags_per_min": 300,                  # ForcAD default is often ~ this; autotune refines
        "autotune": True,
        "order": "newest_first",
        "min_flags_per_min": 30,
        "max_flags_per_min": 2000,
        "global_backoff": 15,
    },

    # ForcAD responds with a JSON list of {"flag","msg","status":bool}; the bool is
    # authoritative (handled in verdicts.py). These regexes split status=false msgs
    # into drop vs resubmit, and cover plain-text fallbacks.
    "verdicts": {
        "accepted": r"(?i)accepted",
        "resubmit": r"(?i)game (?:not started|is paused|over|is not)|not started|is paused|"
                    r"can.?t submit|too fast|rate.?limit|try later|queue|later",
        "drop":     r"(?i)invalid|your own|own flag|too old|expired|already|nop team|not found|no such",
    },

    "limits": {
        "flags_per_submit": 100,
        "min_seconds_between_submits": 1.0,    # be gentle with the jury
        "exploit_timeout": 8,
        "max_workers": 20,
    },

    # ---- v2 (all optional; safe defaults) ----
    "flag_lifetime_seconds": 600,              # 2026 rules: 10 rounds * 60 s
    "retry": {"max_tries": 40, "backoff": [2, 5, 10, 30]},

    "collectors": {
        "hard_timeout": 10,
        "isolation": "thread",
        "subprocess_services": [],             # add pwn service names here (killable procs)
        "hot_reload": True,
        "quarantine": {"err_ratio": 0.9, "rounds": 3, "cooldown": 120},
        "target_cooldown": 60,
        "local_enabled": True,                 # False on a pure submit server for the team
    },

    "gui": {
        "enabled": True,
        "host": "127.0.0.1",                   # teammates pushing in: set to your VPN IP + a token
        "port": 8070,
        "token": None,                         # set a shared string if host != 127.0.0.1
        "poll_ms": 1500,
        "open_browser": True,                  # auto-open the dashboard on --loop (CLI: --no-open)
    },
}


def resolve_address(target, service, base_port):
    # ForcAD: host is the team IP from attack_data; port is the service's fixed port.
    return (target["host"], base_port)
