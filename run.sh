#!/usr/bin/env bash
# Convenience wrapper for the A&D training range (bash / Git Bash).
# Usage: ./run.sh <up|down|rebuild|ps|logs|board|attack|token|help>
set -euo pipefail
cd "$(dirname "$0")"

require_docker() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not reachable. Start Docker Desktop and try again." >&2
    exit 1
  fi
}

board_url() {
  local p=8090
  if [ -f .env ]; then
    p=$(grep -E '^[[:space:]]*SCOREBOARD_PORT[[:space:]]*=' .env | head -1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')
    [ -z "$p" ] && p=8090
  fi
  echo "http://127.0.0.1:$p"
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  local)   python run_local.py "$@";;
  up)      require_docker; python gen_compose.py; docker-compose up -d --build
           echo; echo "Scoreboard: $(board_url) (give the checker a tick or two)";;
  down)    docker-compose down -v;;
  rebuild) require_docker; docker-compose up -d --build;;
  ps)      docker-compose ps;;
  logs)    if [ $# -gt 0 ]; then docker-compose logs -f "$1"; else docker-compose logs -f; fi;;
  board)   python -m webbrowser "$(board_url)" 2>/dev/null || echo "open $(board_url)";;
  attack)  python attacker/attack.py "$@";;
  farm)    python farm/farm.py "$@";;
  token)   python -c "import hmac,hashlib; e={l.split('=',1)[0].strip():l.split('=',1)[1].strip() for l in open('.env',encoding='utf-8') if '=' in l and not l.strip().startswith('#')}; print(hmac.new(e.get('GAME_SECRET','').encode(), e.get('MY_TEAM','team1').encode(), hashlib.sha256).hexdigest()[:16])";;
  *)       echo "Usage: ./run.sh <local|up|down|rebuild|ps|logs|board|attack|farm|token|help>";;
esac
