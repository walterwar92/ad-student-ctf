<#
  install-shortcut.ps1 — create the "A&D Farm" shortcut on this PC's Desktop.
  It launches deploy\windows\farm-dashboard.ps1 (dashboard + connect to server).
  Re-run any time to refresh it.
#>
$ErrorActionPreference = "Stop"
$repo    = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$target  = Join-Path $repo "deploy\windows\farm-dashboard.ps1"
$desktop = [Environment]::GetFolderPath("Desktop")
$lnkPath = Join-Path $desktop "A&D Farm.lnk"
$psExe   = (Get-Command powershell.exe).Source

$sh = New-Object -ComObject WScript.Shell
$sc = $sh.CreateShortcut($lnkPath)
$sc.TargetPath       = $psExe
$sc.Arguments        = "-ExecutionPolicy Bypass -NoExit -File `"$target`""
$sc.WorkingDirectory = $repo
$sc.IconLocation     = "$env:SystemRoot\System32\SHELL32.dll,13"
$sc.Description      = "A&D Student CTF — farm dashboard + server"
$sc.Save()
Write-Host "Created shortcut: $lnkPath" -ForegroundColor Green
