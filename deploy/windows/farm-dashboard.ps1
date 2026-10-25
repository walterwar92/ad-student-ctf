<#
  farm-dashboard.ps1 — one click: open the farm dashboard and connect to the
  боевой server (this is what the Desktop shortcut runs).

  If deploy\deploy.env points at a server, it: starts the farm there
  (systemctl start ad-ctf-farm), opens an SSH tunnel localhost:PORT ->
  server 127.0.0.1:PORT (so the control API stays private on the server), and
  opens the dashboard in your browser.

  If no server is configured yet, it runs the farm locally and opens the
  dashboard at http://127.0.0.1:PORT.
#>
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

# --- parse deploy/deploy.env (KEY=VALUE) ---
$cfg = @{}
$envFile = Join-Path $repo "deploy\deploy.env"
if (Test-Path $envFile) {
  Get-Content $envFile | ForEach-Object {
    $l = $_.Trim()
    if ($l -and -not $l.StartsWith("#") -and $l.Contains("=")) {
      $kv = $l.Split("=", 2); $cfg[$kv[0].Trim()] = $kv[1].Trim()
    }
  }
}
$port = if ($cfg.DASHBOARD_PORT) { $cfg.DASHBOARD_PORT } else { "8070" }
# the example file ships SERVER_HOST=10.60.X.2 — treat an unfilled "X" as "no server"
$haveServer = $cfg.ContainsKey("SERVER_HOST") -and $cfg.SERVER_HOST -and ($cfg.SERVER_HOST -notmatch "[Xx]")

if ($haveServer) {
  $sshArgs = @()
  if ($cfg.SERVER_SSH_PORT) { $sshArgs += @("-p", $cfg.SERVER_SSH_PORT) }
  if ($cfg.SERVER_SSH_KEY)  { $sshArgs += @("-i", ($cfg.SERVER_SSH_KEY -replace "^~", $env:USERPROFILE)) }
  $user   = if ($cfg.SERVER_USER) { $cfg.SERVER_USER } else { "root" }
  $target = "$user@$($cfg.SERVER_HOST)"

  Write-Host "Starting farm on $target ..." -ForegroundColor Cyan
  & ssh @sshArgs $target "systemctl start ad-ctf-farm" 2>$null

  $fwd = "$($port):127.0.0.1:$($port)"
  Write-Host "Opening SSH tunnel localhost:$port -> server 127.0.0.1:$port ..." -ForegroundColor Cyan
  Start-Process ssh -ArgumentList (@("-N", "-L", $fwd) + $sshArgs + @($target))
  Start-Sleep -Seconds 2
  Start-Process "http://127.0.0.1:$port"
  Write-Host "`nDashboard:  http://127.0.0.1:$port" -ForegroundColor Green
  Write-Host "Close the background SSH window to drop the tunnel. `deploy.sh logs` for farm output."
}
else {
  $cfgPy = if (Test-Path "farm\config.prod.py") { "farm/config.prod.py" } else { "farm/config.forcad.py" }
  Write-Host "No server set in deploy\deploy.env — running the farm locally with $cfgPy." -ForegroundColor Yellow
  if ($cfgPy -eq "farm/config.forcad.py") {
    Write-Host "(That config still has placeholder token/ports — fill farm\config.prod.py for real attacks.)" -ForegroundColor Yellow
  }
  Start-Process "http://127.0.0.1:$port"
  & python farm/farm.py --config $cfgPy --loop --no-open --gui-port $port
}
