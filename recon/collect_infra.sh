#!/usr/bin/env bash
# ===========================================================================
# recon/collect_infra.sh — snapshot the real A&D infrastructure FROM A HOST
# THAT IS INSIDE THE GAME VPN (your team server / your box). READ-ONLY: it only
# fetches attack_data, lists local listening ports, inspects docker, and copies
# the service sources that live on YOUR OWN box. It changes nothing in the game.
#
#   bash recon/collect_infra.sh                       # default http://10.10.10.10
#   bash recon/collect_infra.sh https://GAME_HOST     # if only HTTPS is exposed
#   BASE=http://10.10.10.10 SRC_ROOTS="/opt /root /srv" bash recon/collect_infra.sh
#
# Output: recon/out/*  +  recon/out/infra_bundle.tar.gz   (send that back to me)
# ===========================================================================
set -u
cd "$(dirname "$0")/.."                               # repo root
BASE="${1:-${BASE:-http://10.10.10.10}}"
OUT="recon/out"
SRC_ROOTS="${SRC_ROOTS:-/opt /root /home /srv $(pwd)}"
CURL=(curl -s --noproxy '*' --max-time 8)
case "$BASE" in https://*) CURL+=(-k) ;; esac        # tolerate self-signed on HTTPS

mkdir -p "$OUT/sources"
echo "== A&D infra snapshot =="
echo "base   : $BASE"
echo "out    : $OUT"
echo "when   : $(date -u 2>/dev/null)"
echo "host   : $(hostname 2>/dev/null) / $(id -un 2>/dev/null)"
echo

# --- 1) attack_data (try both known client paths) --------------------------
echo ">> [1/5] attack_data"
AD_OK=""
for p in /api/client/attack_data /api/attack_data; do
  if "${CURL[@]}" "$BASE$p" -o "$OUT/attack_data.json" 2>/dev/null \
     && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/attack_data.json" 2>/dev/null; then
    echo "   OK  $BASE$p  ($(wc -c <"$OUT/attack_data.json" | tr -d ' ') bytes)"
    echo "$BASE$p" > "$OUT/attack_data.url"; AD_OK=1; break
  fi
done
[ -z "$AD_OK" ] && echo "   !! could not fetch valid attack_data JSON (check VPN / BASE / path)"

# derive service names + target IPs from attack_data (forcad shape tolerant)
if [ -n "$AD_OK" ]; then
  python3 - "$OUT/attack_data.json" > "$OUT/services.txt" 2> "$OUT/targets.txt" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
svcs, ips = set(), set()
def ipish(s):
    return isinstance(s, str) and s.count(".") == 3
# forcad: {service: {team_ip: [flag_id,...]}}
if isinstance(d, dict):
    for k, v in d.items():
        if isinstance(v, dict):
            svcs.add(k)
            for ip in v:
                if ipish(ip): ips.add(ip)
for s in sorted(svcs): print(s)
for ip in sorted(ips): print(ip, file=sys.stderr)
PY
  echo "   services: $(paste -sd' ' "$OUT/services.txt" 2>/dev/null)"
  echo "   targets : $(paste -sd' ' "$OUT/targets.txt" 2>/dev/null)"
fi
echo

# --- 2) local listening TCP ports ------------------------------------------
echo ">> [2/5] local listening ports -> $OUT/ports.txt"
{ ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null \
  || awk 'NR>1{split($2,a,":");printf "  port %d (hex %s)\n", strtonum("0x"a[2]), a[2]}' /proc/net/tcp 2>/dev/null; } \
  > "$OUT/ports.txt"
sed 's/^/   /' "$OUT/ports.txt" | head -n 25
echo

# --- 3) docker state -------------------------------------------------------
echo ">> [3/5] docker state -> $OUT/docker.txt"
{
  if command -v docker >/dev/null 2>&1; then
    echo "### docker ps"
    docker ps --format '{{.ID}}  {{.Image}}  [{{.Ports}}]  {{.Names}}' 2>/dev/null
    echo; echo "### mounts / source dirs per container"
    for c in $(docker ps -q 2>/dev/null); do
      echo "--- $c $(docker inspect --format '{{.Name}} image={{.Config.Image}}' "$c" 2>/dev/null)"
      docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Type}}){{"\n"}}{{end}}' "$c" 2>/dev/null
    done
  else
    echo "(docker not installed / not in PATH)"
  fi
} > "$OUT/docker.txt" 2>&1
sed 's/^/   /' "$OUT/docker.txt" | head -n 30
echo

# --- 4) find + copy service sources (compose files + their dirs, bind mounts)
echo ">> [4/5] service sources -> $OUT/sources/"
: > "$OUT/source_dirs.txt"
# 4a. docker-compose / compose files under the likely roots
for root in $SRC_ROOTS; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 4 \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' \) \
       2>/dev/null >> "$OUT/compose_files.txt"
done
sort -u -o "$OUT/compose_files.txt" "$OUT/compose_files.txt" 2>/dev/null || true
while IFS= read -r cf; do
  [ -n "$cf" ] && dirname "$cf"
done < "$OUT/compose_files.txt" >> "$OUT/source_dirs.txt"
# 4b. bind-mount source dirs discovered from docker inspect
if command -v docker >/dev/null 2>&1; then
  for c in $(docker ps -q 2>/dev/null); do
    docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$c" 2>/dev/null
  done >> "$OUT/source_dirs.txt"
fi
sort -u -o "$OUT/source_dirs.txt" "$OUT/source_dirs.txt" 2>/dev/null || true
# copy each discovered dir (skip volumes/junk, cap size so we don't grab the world)
i=0
while IFS= read -r d; do
  [ -d "$d" ] || continue
  case "$d" in /|/proc|/sys|/dev|/var/lib/docker*|*/node_modules|*/.git) continue ;; esac
  i=$((i+1)); dst="$OUT/sources/$(echo "$d" | sed 's#^/##; s#/#__#g')"
  mkdir -p "$dst"
  tar -C "$d" --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='node_modules' --exclude='*.sock' --exclude='data' -cf - . 2>/dev/null \
      | tar -C "$dst" -xf - 2>/dev/null
  echo "   copied: $d"
done < "$OUT/source_dirs.txt"
[ "$i" = "0" ] && echo "   (no source dirs auto-found — tar them manually: tar czf src.tgz <service_dir>)"
echo

# --- 5) bundle -------------------------------------------------------------
echo ">> [5/5] bundling"
tar -C recon -czf "$OUT/infra_bundle.tar.gz" \
    --exclude='out/infra_bundle.tar.gz' out 2>/dev/null \
  && echo "   wrote recon/out/infra_bundle.tar.gz ($(wc -c <"$OUT/infra_bundle.tar.gz" | tr -d ' ') bytes)"
echo
echo "== done. Send back: recon/out/attack_data.json, services.txt, targets.txt,"
echo "   ports.txt, docker.txt, and recon/out/sources/ (or recon/out/infra_bundle.tar.gz)."
echo "   Paste them here or scp them off the box. Then I'll write per-service exploits + patches."
