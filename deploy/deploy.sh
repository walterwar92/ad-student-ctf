#!/usr/bin/env bash
# ===========================================================================
# deploy/deploy.sh — ship the A&D range + farm to your team server and run it.
# Runs from THIS PC (Linux / macOS / Windows Git Bash). Stdlib tools only:
# ssh, tar, (scp). No rsync needed.
#
#   cp deploy/deploy.env.example deploy/deploy.env   # then edit it
#   ./deploy/deploy.sh all          # push code + install deps + systemd unit
#   ./deploy/deploy.sh wg-push      # upload your WireGuard *.conf to the server
#   ./deploy/deploy.sh wg up        # bring all server tunnels up (coexisting)
#   ./deploy/deploy.sh start        # start the farm (reads farm/config.prod.py)
#   ./deploy/deploy.sh status|logs|stop|token|ssh
#
# Nothing here attacks on its own: `start` only launches the farm, which reads
# your config.prod.py (your IP, token, service ports). Fill those first.
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")/.."                      # repo root
ENV_FILE="deploy/deploy.env"

[ -f "$ENV_FILE" ] || { echo "Missing $ENV_FILE — copy deploy.env.example and edit it." >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${SERVER_HOST:?set SERVER_HOST in deploy.env}"
: "${SERVER_USER:=root}"; : "${SERVER_SSH_PORT:=22}"; : "${SERVER_DIR:=/opt/ad-ctf}"
: "${SERVER_PYTHON:=python3}"; : "${DASHBOARD_PORT:=8070}"

SSH_OPTS=(-p "$SERVER_SSH_PORT" -o StrictHostKeyChecking=accept-new)
[ -n "${SERVER_SSH_KEY:-}" ] && SSH_OPTS+=(-i "${SERVER_SSH_KEY/#\~/$HOME}")
SSH=(ssh "${SSH_OPTS[@]}" "${SERVER_USER}@${SERVER_HOST}")
TARGET="${SERVER_USER}@${SERVER_HOST}"

remote() { "${SSH[@]}" "$@"; }

push_code() {
  echo ">> packing repo (excluding git/runtime/secrets) and uploading to ${TARGET}:${SERVER_DIR}"
  remote "mkdir -p '$SERVER_DIR' /etc/ad-ctf"
  tar --exclude='./.git' --exclude='./run' --exclude='*/data' --exclude='./data' \
      --exclude='*/__pycache__' --exclude='*.pyc' --exclude='*.db' --exclude='*.db-*' \
      --exclude='*.log' --exclude='./deploy/deploy.env' --exclude='./deploy/wg-multi/conf' \
      -czf - . | remote "tar xzf - -C '$SERVER_DIR'"
  echo ">> code is on the server."
}

setup() {
  echo ">> installing deps + systemd unit on the server"
  # deps: python3 + wireguard-tools (apt-based distros; skip silently otherwise)
  remote "command -v apt-get >/dev/null 2>&1 && (apt-get update -qq && \
          DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 wireguard-tools iproute2 curl) || true"
  # systemd unit: resolve python to an ABSOLUTE path ON THE SERVER (systemd
  # ExecStart must be absolute), then substitute paths into the unit.
  remote "set -e; PY=\$(command -v ${SERVER_PYTHON} || echo /usr/bin/python3); \
          sed -e 's#__DIR__#${SERVER_DIR}#g' -e \"s#__PY__#\${PY}#g\" \
              '${SERVER_DIR}/deploy/farm.service' > /etc/systemd/system/ad-ctf-farm.service; \
          chmod +x '${SERVER_DIR}/deploy/wg-multi/wg-multi.sh'; \
          systemctl daemon-reload; systemctl enable ad-ctf-farm >/dev/null 2>&1 || true"
  remote "test -f '${SERVER_DIR}/farm/config.prod.py' || \
          echo '  [!] farm/config.prod.py not found on server yet — create it (see deploy/config.prod.example.py) before start.'"
  echo ">> setup done. Fill farm/config.prod.py, then: ./deploy/deploy.sh start"
}

wg_push() {
  local n; n=$(ls -1 deploy/wg-multi/conf/*.conf 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" = "0" ] && { echo "No *.conf in deploy/wg-multi/conf/ — drop the organizers' WireGuard configs there first." >&2; exit 1; }
  echo ">> uploading $n WireGuard config(s) to ${TARGET}:/etc/ad-ctf/wg/"
  remote "mkdir -p /etc/ad-ctf/wg && chmod 700 /etc/ad-ctf/wg"
  tar -czf - -C deploy/wg-multi/conf . | remote "tar xzf - -C /etc/ad-ctf/wg && chmod 600 /etc/ad-ctf/wg/*.conf"
  echo ">> done. Bring them up:  ./deploy/deploy.sh wg up"
}

case "${1:-help}" in
  push)    push_code ;;
  setup)   setup ;;
  all)     push_code; setup ;;
  wg-push) wg_push ;;
  wg)      shift; remote "'${SERVER_DIR}/deploy/wg-multi/wg-multi.sh' ${*:-status}" ;;
  start)   remote "systemctl restart ad-ctf-farm && sleep 1 && systemctl --no-pager -l status ad-ctf-farm | head -n 12" ;;
  stop)    remote "systemctl stop ad-ctf-farm && echo stopped" ;;
  status)  remote "systemctl --no-pager -l status ad-ctf-farm | head -n 20; echo; '${SERVER_DIR}/deploy/wg-multi/wg-multi.sh' status || true" ;;
  logs)    remote "journalctl -u ad-ctf-farm -f -n 80" ;;
  token)   remote "cd '${SERVER_DIR}' && ${SERVER_PYTHON} - <<'PY'
import importlib.util,os
p='farm/config.prod.py'
if os.path.exists(p):
    s=importlib.util.spec_from_file_location('c',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    print('submit token in config.prod.py:', m.CONFIG.get('submitter',{}).get('token'))
else:
    print('no farm/config.prod.py yet')
PY" ;;
  ssh)     exec "${SSH[@]}" ;;
  help|*)  sed -n '2,20p' "$0" ;;
esac
