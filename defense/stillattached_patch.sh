#!/usr/bin/env bash
# Re-apply the SAFE StillAttached defense patch on the box.
#
#   #2 clamp note.data to 256 hex (128 B) — breaks the UAF heap-groom used by the
#      note-spray farms (observed legit notes are <=64 hex, so this is SLA-safe).
#
# WARNING / DO NOT RE-ADD #1: an earlier version also owner-scoped GET /api/targets
# (dropping foreign "mine":false entries). That BROKE SLA — the service deliberately
# lists ALL targets with a per-entry `mine` flag (a shared "target board"), and the
# CHECKER validates that listing, so filtering it put StillAttached into MUMBLE for
# several rounds. It has been REMOVED on purpose. Do not re-add a list_targets filter.
#
# This clamp does NOT stop the attach+read_reg UAF channel (farm 10.61.2.5): that is a
# memory bug in the ELF engine, not reachable from web input validation. See
# defense/stillattached_uaf.md.
#
# Engine (bin/stillattached) is NOT touched; flags live in a docker volume.
# ALWAYS watch the scoreboard for 1-2 rounds after applying; revert if SLA drops:
#   cp "$(ls -t web/main.py.bak_* | tail -1)" web/main.py && rebuild (see below)
#
# Run on the vulnbox:  sudo bash defense/stillattached_patch.sh
set -euo pipefail
DIR=${STILL_DIR:-/opt/services/StillAttached}
MAIN="$DIR/web/main.py"
[ -f "$MAIN" ] || { echo "not found: $MAIN (set STILL_DIR)"; exit 1; }

cp "$MAIN" "$MAIN.bak_$(date +%Y%m%d_%H%M%S)"

python3 - "$MAIN" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

# --- patch #2: clamp note.data size (8192 -> 256 hex). SLA-safe: legit notes <=64 hex ---
old2 = "max_length=8192, pattern="
new2 = "max_length=256, pattern="
if new2 in s and old2 not in s:
    print("clamp already applied")
elif s.count(old2) == 1:
    s = s.replace(old2, new2); print("clamp applied (note.data 8192 -> 256 hex)")
else:
    raise SystemExit("clamp anchor not found/unique (count=%d)" % s.count(old2))

open(p, "w").write(s)
PY

python3 -c "import ast; ast.parse(open('$MAIN').read()); print('SYNTAX OK')"

cd "$DIR"
docker compose -f compose.yml build web
docker compose -f compose.yml up -d --no-deps web
echo "done. verify SLA (note set 64hex -> 200 and read-back equal) + 512-hex note -> 422"
echo "then WATCH THE SCOREBOARD: StillAttached must stay OK. If MUMBLE, revert (see header)."
