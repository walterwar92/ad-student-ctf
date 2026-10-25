<#
  wg-multi.ps1 — manage several WireGuard tunnels on THIS Windows PC.
  Run in an ELEVATED PowerShell (tunnels are installed as Windows services).
  Requires the official WireGuard for Windows (wireguard.exe).

  Put the organizers' *.conf in deploy\wg-multi\conf\ , then:
    .\wg-multi.ps1 import     # install every conf as a tunnel service
    .\wg-multi.ps1 up         # start all tunnels
    .\wg-multi.ps1 status     # show tunnel services + state
    .\wg-multi.ps1 down       # stop all tunnels
    .\wg-multi.ps1 remove     # uninstall all tunnel services

  NOTE: Windows has no fwmark policy routing. If several configs claim the same
  game subnet, only one carries it at a time (Windows picks by route metric), so
  on the PC treat extra tunnels as a backup identity / manual access. The TRUE
  "attack through all tunnels at once" balancing runs on the Linux server
  (deploy/wg-multi/wg-multi.sh + farm/vpn_balance.py). The боевой server is the
  main attack host; this PC is for control and a spare path.
#>
param([string]$cmd = "status")
$ErrorActionPreference = "Stop"
$confDir = Resolve-Path (Join-Path $PSScriptRoot "..\wg-multi\conf")
$wg = "$env:ProgramFiles\WireGuard\wireguard.exe"
if (-not (Test-Path $wg)) { Write-Host "WireGuard for Windows not found at $wg — install it from wireguard.com." -ForegroundColor Yellow; if ($cmd -ne 'status') { exit 1 } }

function Confs { Get-ChildItem -Path $confDir -Filter *.conf -ErrorAction SilentlyContinue }
function TunnelName($f) { [IO.Path]::GetFileNameWithoutExtension($f) }

switch ($cmd) {
  "import" {
    $c = Confs; if (-not $c) { Write-Host "No *.conf in $confDir"; exit 1 }
    foreach ($f in $c) { Write-Host ">> installing tunnel $(TunnelName $f.Name)"; & $wg /installtunnelservice $f.FullName }
  }
  "remove" { foreach ($f in Confs) { Write-Host ">> removing $(TunnelName $f.Name)"; & $wg /uninstalltunnelservice (TunnelName $f.Name) } }
  "up"     { foreach ($f in Confs) { $s = "WireGuardTunnel`$$(TunnelName $f.Name)"; Write-Host ">> start $s"; Start-Service $s -ErrorAction SilentlyContinue } }
  "down"   { foreach ($f in Confs) { $s = "WireGuardTunnel`$$(TunnelName $f.Name)"; Write-Host ">> stop $s";  Stop-Service  $s -ErrorAction SilentlyContinue } }
  "status" {
    Write-Host "configs in $confDir :"; Confs | ForEach-Object { " - $($_.Name)" } | Write-Host
    Write-Host "`ntunnel services:"; Get-Service "WireGuardTunnel`$*" -ErrorAction SilentlyContinue |
      Format-Table Status, Name -AutoSize
  }
  default  { Get-Content $PSCommandPath | Select-String '^\s{4}\.' | ForEach-Object { $_.Line } }
}
