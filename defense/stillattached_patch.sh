#!/usr/bin/env bash
# Re-apply StillAttached defense patches on the box. Idempotent + SLA-safe.
#   #1 owner-scope GET /api/targets (drop foreign mine:false)
#   #2 clamp note.data to 256 hex (128 B) to break the UAF heap-groom
# Engine (bin/stillattached) is NOT touched; flags live in a docker volume.
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

# --- patch #1: owner-scope list_targets ---
old1 = '    return await rpc("list_targets", user["id"], after=after)'
new1 = ('    data = await rpc("list_targets", user["id"], after=after)\n'
        '    if isinstance(data, dict) and isinstance(data.get("targets"), list):\n'
        '        data["targets"] = [t for t in data["targets"] if t.get("mine")]\n'
        '    return data')
if new1 in s:
    print("patch#1 already applied")
elif s.count(old1) == 1:
    s = s.replace(old1, new1); print("patch#1 applied")
else:
    raise SystemExit("patch#1 anchor not found/unique (count=%d)" % s.count(old1))

# --- patch #2: clamp note.data size (8192 -> 256 hex) ---
old2 = "max_length=8192, pattern="
new2 = "max_length=256, pattern="
if new2 in s and old2 not in s:
    print("patch#2 already applied")
elif s.count(old2) == 1:
    s = s.replace(old2, new2); print("patch#2 applied")
else:
    raise SystemExit("patch#2 anchor not found/unique (count=%d)" % s.count(old2))

open(p, "w").write(s)
PY

python3 -c "import ast; ast.parse(open('$MAIN').read()); print('SYNTAX OK')"

cd "$DIR"
docker compose -f compose.yml build web
docker compose -f compose.yml up -d --no-deps web
echo "done. verify SLA (note set/get) + GET /api/targets (only mine) + 512-hex note -> 422"
