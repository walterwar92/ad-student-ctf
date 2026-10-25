#!/usr/bin/env bash
# ===========================================================================
# recon/collect_vnek.sh — focused, READ-ONLY snapshot of the `vnek` service
# (Go "вНеконтакте", port 28080) from YOUR OWN team box inside the game VPN.
#
# In A&D every team runs an IDENTICAL copy of the service, so the source taken
# from our box is byte-for-byte what the victims run. This script only READS:
# it lists listeners, inspects docker, copies the vnek source that lives on our
# box, probes the local service over HTTP, and pulls vnek's flag_id from
# attack_data. It changes nothing in the game and touches no other service.
#
#   ssh root@10.60.7.2            # our box (team 7 = Prime); then, from anywhere:
#   bash collect_vnek.sh          # paste this file, or scp it over and run it
#   PORT=28080 BASE=http://10.10.10.10 bash collect_vnek.sh
#
# Output: prints everything to stdout (copy it back to the chat) AND writes
#         /tmp/vnek_recon/ + /tmp/vnek_recon.tar.gz (scp that if paste is big).
# ===========================================================================
set -u
PORT="${PORT:-28080}"
BASE="${BASE:-http://10.10.10.10}"
SRC_ROOTS="${SRC_ROOTS:-/opt /root /srv /home /ctf /app $(pwd)}"
O=/tmp/vnek_recon
rm -rf "$O" 2>/dev/null; mkdir -p "$O/src"
MAXCAT_LINES="${MAXCAT_LINES:-1500}"   # per-file cat cap when dumping source
CURL=(curl -s --noproxy '*' --max-time 8)
case "$BASE" in https://*) CURL+=(-k) ;; esac

say(){ printf '\n========== %s ==========\n' "$*"; }

say "0) host / when"
{ echo "host : $(hostname 2>/dev/null) / user $(id -un 2>/dev/null)"; echo "date : $(date -u 2>/dev/null)"; echo "port : $PORT   base(attackdata): $BASE"; } | tee "$O/host.txt"

# --- 1) is vnek listening? --------------------------------------------------
say "1) listeners on :$PORT"
{ ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null; } > "$O/ports_all.txt"
grep -E "[:.]$PORT([^0-9]|$)" "$O/ports_all.txt" | tee "$O/port_hit.txt"
[ -s "$O/port_hit.txt" ] || echo "   (nothing on :$PORT locally — check the port / that you are on the box)"

# --- 2) docker overview -----------------------------------------------------
say "2) docker ps"
HAVE_DOCKER=""; command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1 && HAVE_DOCKER=1
if [ -n "$HAVE_DOCKER" ]; then
  docker ps --format '{{.ID}}  {{.Image}}  [{{.Ports}}]  {{.Names}}' 2>/dev/null | tee "$O/docker_ps.txt"
else
  echo "   (docker unavailable or not permitted — will fall back to filesystem search)" | tee "$O/docker_ps.txt"
fi

# --- 3) locate the vnek container ------------------------------------------
say "3) locate vnek container"
CID=""
if [ -n "$HAVE_DOCKER" ]; then
  CID=$(docker ps -q --filter "publish=$PORT" 2>/dev/null | head -1)
  [ -z "$CID" ] && CID=$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null \
                         | grep -iE 'vnek|neko|vkontak|contakt|vk' | awk '{print $1}' | head -1)
fi
echo "vnek container id = ${CID:-<none>}" | tee "$O/vnek_cid.txt"

# --- 4) inspect image + bind mounts (= host source dirs) --------------------
say "4) inspect vnek container"
SRC_DIRS=""
if [ -n "$CID" ]; then
  docker inspect "$CID" --format 'IMAGE={{.Config.Image}}
WORKDIR={{.Config.WorkingDir}}
ENTRYPOINT={{json .Config.Entrypoint}}
CMD={{json .Config.Cmd}}
ENV={{json .Config.Env}}' 2>/dev/null | tee "$O/vnek_inspect.txt"
  echo "--- mounts (bind Source dirs hold the editable source) ---" | tee -a "$O/vnek_inspect.txt"
  docker inspect "$CID" --format '{{range .Mounts}}{{.Type}}  {{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' 2>/dev/null | tee -a "$O/vnek_inspect.txt"
  SRC_DIRS=$(docker inspect "$CID" --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' 2>/dev/null)
fi

# --- 5) find source dirs on the host (compose + go.mod mentioning vnek) -----
say "5) candidate source dirs on host"
for root in $SRC_ROOTS; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 5 \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' -o -name 'go.mod' \) 2>/dev/null
done | sort -u > "$O/candidate_files.txt"
# keep dirs whose tree looks like vnek (name match, or go.mod/compose referencing it)
: > "$O/src_dirs.txt"
{ printf '%s\n' "$SRC_DIRS"; while IFS= read -r f; do [ -n "$f" ] && dirname "$f"; done < "$O/candidate_files.txt"; } \
  | sort -u | while IFS= read -r d; do
      [ -d "$d" ] || continue
      case "$d" in /|/proc|/sys|/dev|/var/lib/docker*|*/node_modules|*/.git) continue ;; esac
      if echo "$d" | grep -qiE 'vnek|neko|vkontak|vk' \
         || grep -rilq 'vnek' "$d"/*.y*ml "$d"/go.mod 2>/dev/null \
         || [ -n "$SRC_DIRS" ]; then echo "$d"; fi
    done | sort -u | tee "$O/src_dirs.txt"
[ -s "$O/src_dirs.txt" ] || { echo "   (no obvious vnek dir — dumping ALL candidate dirs so we don't miss it)"; \
   while IFS= read -r f; do [ -n "$f" ] && dirname "$f"; done < "$O/candidate_files.txt" | sort -u | tee "$O/src_dirs.txt" >/dev/null; }

# --- 6) copy the source dirs (read-only tar|untar, junk excluded) -----------
say "6) copy source -> $O/src"
i=0
while IFS= read -r d; do
  [ -d "$d" ] || continue
  i=$((i+1)); dst="$O/src/$(echo "$d" | sed 's#^/##; s#/#__#g')"
  mkdir -p "$dst"
  tar -C "$d" --exclude='.git' --exclude='node_modules' --exclude='*.sock' \
      --exclude='data' --exclude='*.db' --exclude='vendor' -cf - . 2>/dev/null \
      | tar -C "$dst" -xf - 2>/dev/null && echo "   copied: $d"
done < "$O/src_dirs.txt"
# if source is baked into the image (no bind mount), pull it out of the container
if [ "$i" = "0" ] && [ -n "$CID" ]; then
  echo "   no host source dirs — extracting from container $CID"
  WD=$(docker inspect "$CID" --format '{{.Config.WorkingDir}}' 2>/dev/null); WD="${WD:-/app}"
  docker exec "$CID" sh -c 'find / -maxdepth 6 -name "*.go" 2>/dev/null | head -50' > "$O/container_go_files.txt" 2>/dev/null
  docker cp "$CID:$WD" "$O/src/container_workdir" 2>/dev/null && echo "   docker cp $CID:$WD"
  sed 's/^/   go: /' "$O/container_go_files.txt" 2>/dev/null | head -20
fi

# --- 7) dump the source tree + key files to stdout --------------------------
say "7) source tree"
( cd "$O/src" && find . -type f 2>/dev/null | sed 's#^\./##' | sort ) | tee "$O/src_tree.txt"
say "7b) source files (go / mod / yaml / Dockerfile / conf)"
find "$O/src" -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name '*.y*ml' \
     -o -iname 'Dockerfile*' -o -name '*.env' -o -name '*.sql' -o -name '*.toml' \
     -o -name '*.json' -o -name '*.conf' -o -name '*.sh' \) 2>/dev/null | sort | while IFS= read -r f; do
  rel="${f#$O/src/}"
  case "$rel" in */go.sum) echo; echo "----- FILE: $rel (go.sum — skipped, $(wc -l <"$f" 2>/dev/null) lines) -----"; continue ;; esac
  n=$(wc -l <"$f" 2>/dev/null)
  echo; echo "----- FILE: $rel ($n lines) -----"
  head -n "$MAXCAT_LINES" "$f" 2>/dev/null
  [ "${n:-0}" -gt "$MAXCAT_LINES" ] && echo "----- ...(truncated at $MAXCAT_LINES lines; full copy in the tarball) -----"
done

# --- 8) live probe of the local service ------------------------------------
say "8) live HTTP probe http://127.0.0.1:$PORT"
B="http://127.0.0.1:$PORT"
P=(curl -s -i --max-time 5 --noproxy '*')
{ echo "### GET / ###";        "${P[@]}" "$B/"            | head -40; echo;
  echo "### GET /api ###";     "${P[@]}" "$B/api"         | head -20; echo;
  echo "### GET /api/ ###";    "${P[@]}" "$B/api/"        | head -20; echo;
  echo "### GET /robots.txt ###"; "${P[@]}" "$B/robots.txt" | head -10; echo;
  echo "### GET /metrics ###"; "${P[@]}" "$B/metrics"     | head -10; echo;
  echo "### GET /debug/pprof/ ###"; "${P[@]}" "$B/debug/pprof/" | head -10;
} > "$O/http_probe.txt" 2>&1
sed 's/^/   /' "$O/http_probe.txt" | head -120

# --- 9) vnek flag_id from attack_data --------------------------------------
say "9) attack_data -> vnek flag_ids (shows what flag_id means)"
for p in /api/client/attack_data /api/attack_data; do
  "${CURL[@]}" "$BASE$p" -o "$O/attack_data.json" 2>/dev/null \
    && python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$O/attack_data.json" 2>/dev/null \
    && { echo "   OK $BASE$p"; break; }
done
python3 - "$O/attack_data.json" 2>/dev/null <<'PY' | tee "$O/vnek_attackdata.txt"
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: print("(no attack_data:",e,")"); sys.exit()
v=d.get("vnek")
if v is None:
    print("services in attack_data:", ", ".join(k for k in d) if isinstance(d,dict) else type(d))
    print("(no 'vnek' key — maybe inter-team net not open yet, or different name)")
else:
    print("vnek targets/flag_ids (host -> flag_id list):")
    print(json.dumps(v,indent=2)[:3000])
PY

# --- 10) bundle -------------------------------------------------------------
say "10) bundle"
tar -C /tmp -czf /tmp/vnek_recon.tar.gz vnek_recon 2>/dev/null \
  && echo "wrote /tmp/vnek_recon.tar.gz ($(wc -c </tmp/vnek_recon.tar.gz 2>/dev/null) bytes)"
echo
echo "== DONE. Send back: the stdout above (esp. sections 7/7b/8/9),"
echo "   or scp /tmp/vnek_recon.tar.gz off the box if the paste is too big. =="
