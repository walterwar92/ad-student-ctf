<#
  Convenience wrapper for the A&D training range (Windows / PowerShell).
  Usage:  .\run.ps1 <command> [arg]

  Commands:
    local [args]  run the whole range NATIVELY (no Docker/pip) — use this here
    up            generate compose + build & start everything (needs Docker + registry/PyPI access)
    down          stop and remove everything (including the flags DB volume)
    rebuild       rebuild images and restart
    ps            show container status
    logs [name]   follow logs (optionally one service, e.g. logs checksystem)
    board         open the scoreboard in your browser
    attack [args] run the simple attack loop (attacker/attack.py)
    farm [args]   run the config-driven battle farm (farm/farm.py) — for the real test platform
    token         print YOUR team's flag-submission token
    help          this text
#>
param([string]$cmd = "help", [Parameter(ValueFromRemainingArguments=$true)][string[]]$rest)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Require-Docker {
  try { docker info *> $null } catch {
    Write-Host "Docker daemon is not reachable. Start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
  }
}

function Board-Url {
  $p = "8090"
  if (Test-Path .env) {
    $m = Select-String -Path .env -Pattern '^\s*SCOREBOARD_PORT\s*=\s*(\d+)' | Select-Object -First 1
    if ($m) { $p = $m.Matches[0].Groups[1].Value }
  }
  return "http://127.0.0.1:$p"
}

switch ($cmd) {
  "local"   { python run_local.py @rest }
  "up" {
    Require-Docker
    python gen_compose.py
    docker-compose up -d --build
    Write-Host "`nScoreboard: $(Board-Url)   (give the checker a tick or two to go green)" -ForegroundColor Green
  }
  "down"    { docker-compose down -v }
  "rebuild" { Require-Docker; docker-compose up -d --build }
  "ps"      { docker-compose ps }
  "logs"    { if ($rest) { docker-compose logs -f $rest[0] } else { docker-compose logs -f } }
  "board"   { Start-Process (Board-Url) }
  "attack"  { python attacker/attack.py @rest }
  "farm"    { python farm/farm.py @rest }
  "token"   { python -c "import os,hmac,hashlib; e={l.split('=',1)[0].strip():l.split('=',1)[1].strip() for l in open('.env',encoding='utf-8') if '=' in l and not l.strip().startswith('#')}; print(hmac.new(e.get('GAME_SECRET','').encode(), e.get('MY_TEAM','team1').encode(), hashlib.sha256).hexdigest()[:16])" }
  default   {
    Get-Content $PSCommandPath | Select-String -Pattern '^\s{4}\w' -Context 0,0 | ForEach-Object { $_.Line }
    Write-Host "`nUsage: .\run.ps1 <local|up|down|rebuild|ps|logs|board|attack|farm|token|help>"
  }
}
