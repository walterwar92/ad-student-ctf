#!/usr/bin/env bash
# ===========================================================================
# wg-multi.sh — run SEVERAL WireGuard tunnels side by side without them (or the
# server's primary game VPN) fighting over the routing table, and let the farm
# attack through ALL of them.
#
# The problem: every A&D WireGuard config routes the same game subnets
# (10.60.0.0/16, 10.10.10.10). If two tunnels put that route in the MAIN table,
# only one wins — the others are dead, and your primary VPN may break too.
#
# The fix (standard Linux policy routing):
#   * each tunnel gets its OWN routing table  (Table = 1xx in its config, so
#     wg-quick never touches the main table — your primary VPN is untouched);
#   * each tunnel gets a unique fwmark + an `ip rule fwmark <M> lookup <table>`;
#   * the farm marks its outbound sockets (SO_MARK) round-robin across the marks
#     (farm/vpn_balance.py, enabled by FARM_VPN_MARKS) — so each attack leaves
#     through a different tunnel. Unmarked traffic still uses the main table,
#     i.e. the primary VPN, exactly as before.
#
#   sudo ./wg-multi.sh up        # bring every conf/ tunnel up, coexisting
#   sudo ./wg-multi.sh status    # tunnels, rules, per-table routes, mark map
#   sudo ./wg-multi.sh test      # check 10.10.10.10 reachability per tunnel
#   sudo ./wg-multi.sh down      # tear them all down, remove rules
#   ./wg-multi.sh marks          # print the FARM_VPN_MARKS line for the farm
#
# Config source: /etc/ad-ctf/wg/*.conf  (uploaded by deploy.sh wg-push), or set
# WG_CONF_DIR. Each tunnel i -> interface adc<i>, table 10<i>, fwmark 7424+i.
# ===========================================================================
set -euo pipefail

WG_CONF_DIR="${WG_CONF_DIR:-/etc/ad-ctf/wg}"
GEN_DIR=/etc/wireguard
VPN_ENV=/etc/ad-ctf/vpn.env
PRIO_BASE=10000
MARK_BASE=7424            # 0x1D00; marks are MARK_BASE+i

need_root() { [ "$(id -u)" = "0" ] || { echo "run as root (sudo)"; exit 1; }; }
list_confs() { ls -1 "$WG_CONF_DIR"/*.conf 2>/dev/null | sort || true; }

# print "i|basename|iface|table|mark" for every conf
enumerate() {
  local i=0 f base
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    i=$((i+1)); base=$(basename "$f" .conf)
    echo "${i}|${base}|adc${i}|$((100+i))|$((MARK_BASE+i))"
  done < <(list_confs)
}

# write a processed copy of conf $1 into $GEN_DIR/$2.conf with `Table = $3`
# injected into [Interface] (any existing Table line is dropped).
gen_conf() {
  local src="$1" iface="$2" table="$3"
  awk -v t="$table" '
    BEGIN{done=0}
    /^[[:space:]]*\[Interface\][[:space:]]*$/ { print; print "Table = " t; done=1; next }
    /^[[:space:]]*[Tt]able[[:space:]]*=/ { next }        # drop pre-existing Table
    { print }
    END{ if(!done) print "[-] no [Interface] section in " ARGV[1] > "/dev/stderr" }
  ' "$src" > "${GEN_DIR}/${iface}.conf"
  chmod 600 "${GEN_DIR}/${iface}.conf"
}

cmd_up() {
  need_root
  [ -n "$(list_confs)" ] || { echo "no configs in $WG_CONF_DIR (run: deploy.sh wg-push)"; exit 1; }
  mkdir -p "$GEN_DIR" "$(dirname "$VPN_ENV")"
  # loose reverse-path filtering so multi-homed replies are not dropped
  sysctl -wq net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
  local marks=""
  while IFS='|' read -r i base iface table mark; do
    echo ">> [$i] $base -> iface $iface, table $table, fwmark $mark"
    gen_conf "${WG_CONF_DIR}/${base}.conf" "$iface" "$table"
    wg-quick down "$iface" 2>/dev/null || true
    wg-quick up "$iface"
    # marked app traffic -> this tunnel's table; sits above the main table
    ip rule add fwmark "$mark" lookup "$table" priority $((PRIO_BASE+i)) 2>/dev/null || true
    marks="${marks:+$marks,}$mark"
  done < <(enumerate)
  echo "FARM_VPN_MARKS=${marks}" > "$VPN_ENV"
  echo ">> wrote $VPN_ENV  ->  FARM_VPN_MARKS=${marks}"
  echo ">> restart the farm to pick it up:  systemctl restart ad-ctf-farm"
}

cmd_down() {
  need_root
  while IFS='|' read -r i base iface table mark; do
    ip rule del fwmark "$mark" lookup "$table" priority $((PRIO_BASE+i)) 2>/dev/null || true
    wg-quick down "$iface" 2>/dev/null || true
    rm -f "${GEN_DIR}/${iface}.conf"
    echo ">> [$i] $base ($iface) down"
  done < <(enumerate)
  rm -f "$VPN_ENV"
  echo ">> removed $VPN_ENV"
}

cmd_status() {
  echo "=== tunnels (wg show) ==="; wg show 2>/dev/null || echo "(none / need root)"
  echo; echo "=== policy rules (fwmark -> table) ==="; ip rule show 2>/dev/null | grep -E "fwmark|lookup 10[0-9]" || echo "(none)"
  echo; echo "=== map ==="; printf "%s\n" "idx|conf|iface|table|fwmark"; enumerate
  [ -f "$VPN_ENV" ] && { echo; echo "=== $VPN_ENV ==="; cat "$VPN_ENV"; }
  while IFS='|' read -r i base iface table mark; do
    echo "--- table $table ($iface) ---"; ip route show table "$table" 2>/dev/null || true
  done < <(enumerate)
}

cmd_test() {
  local url="${1:-http://10.10.10.10/}"
  echo ">> probing $url through each tunnel (expect a response/redirect, not a timeout)"
  while IFS='|' read -r i base iface table mark; do
    printf "  [%s] %-14s " "$i" "$iface"
    if ip link show "$iface" >/dev/null 2>&1; then
      curl -s -o /dev/null -m 6 --interface "$iface" -w "HTTP %{http_code} in %{time_total}s\n" "$url" \
        || echo "no answer (tunnel down or target unreachable)"
    else echo "iface not up"; fi
  done < <(enumerate)
}

cmd_marks() { local m=""; while IFS='|' read -r i base iface table mark; do m="${m:+$m,}$mark"; done < <(enumerate); echo "FARM_VPN_MARKS=${m}"; }

case "${1:-status}" in
  up) cmd_up ;; down) cmd_down ;; status) cmd_status ;;
  test) shift; cmd_test "${1:-}" ;; marks) cmd_marks ;;
  *) sed -n '2,33p' "$0" ;;
esac
