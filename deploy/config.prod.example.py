# ===== farm/config.prod.py — your REAL game config (GITIGNORED) =====
# On game day:   cp deploy/config.prod.example.py farm/config.prod.py
# then fill the 3 marked values. The farm loads it with:
#   python farm/farm.py --config farm/config.prod.py --loop
#
# It starts from farm/config.forcad.py (already synced to Правила_26: 10.60.N.2,
# 60 s round, 600 s flag life) and overrides ONLY the secret / per-game values,
# so you never hand-edit — and never commit — your token.
import importlib.util
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("forcad_base",
                                               os.path.join(_here, "config.forcad.py"))
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

CONFIG = dict(_base.CONFIG)
resolve_address = _base.resolve_address            # farm reads this too

# ---- 1) YOUR team box (never attacked) --------------------------------------
CONFIG["targets"] = dict(CONFIG["targets"], my_team_ip="10.60.<<YOUR_TEAM_ID>>.2")

# ---- 2) services + their real ports (published at start) --------------------
#       name must match the service_name key in /api/client/attack_data
CONFIG["services"] = {
    "workflow": 0,          # <<-- real port
    "zounds": 0,            # <<-- real port
    "secretscribble": 0,    # <<-- real port
}

# ---- 3) your personal flag-submission token (keep secret) -------------------
CONFIG["submitter"] = dict(CONFIG["submitter"], token="<<YOUR_TEAM_TOKEN>>")
# If the orgs only expose the HTTPS interface, also switch the URLs to it:
# CONFIG["submitter"]  = dict(CONFIG["submitter"],  url="https://GAME_HOST/flags")
# CONFIG["attackdata"] = dict(CONFIG["attackdata"], url="https://GAME_HOST/api/client/attack_data")
