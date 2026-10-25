"""Checksystem configuration, derived from environment variables (see .env)."""
import os
import json
import hmac
import hashlib


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


TEAMS = _int("TEAMS", 10)
TICK_SECONDS = _int("TICK_SECONDS", 30)
FLAG_LIFETIME_TICKS = _int("FLAG_LIFETIME_TICKS", 5)
GAME_SECRET = os.environ.get("GAME_SECRET", "studentctf-local-dev-change-me")
MY_TEAM = os.environ.get("MY_TEAM", "team1")
SCOREBOARD_PORT = _int("SCOREBOARD_PORT", 8080)
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
SERVICES_DIR = os.environ.get("SERVICES_DIR", "/app/services")
HTTP_TIMEOUT = 5

# Service registry: (name, default internal port). The checker module's
# DEFAULT_PORT wins if present.
SERVICES = [("web", 5001), ("crypto", 5002), ("depot", 5003)]


def team_token(name):
    """Deterministic per-team flag-submission token (so the attacker can derive
    its own token without scraping it from anywhere)."""
    return hmac.new(GAME_SECRET.encode(), name.encode(), hashlib.sha256).hexdigest()[:16]


def teams():
    """List of {name, host, token}.

    In Docker, host == the compose service name (team1..teamN).
    For local testing, set TEAMS_JSON='[{"name":"team1","host":"127.0.0.1"}]'.
    """
    env = os.environ.get("TEAMS_JSON")
    if env:
        data = json.loads(env)
        return [
            {"name": t["name"], "host": t.get("host", t["name"]),
             "ports": t.get("ports"), "token": team_token(t["name"])}
            for t in data
        ]
    out = []
    for i in range(1, TEAMS + 1):
        name = "team%d" % i
        out.append({"name": name, "host": name, "token": team_token(name)})
    return out
