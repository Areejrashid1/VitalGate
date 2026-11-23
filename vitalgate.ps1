<#
VitalGate launcher (repo root). Forwards to console\vitalgate.ps1, which runs the SOC console (console/)
on top of the model and pipeline in product/.

  .\vitalgate.ps1 start              console + replay of recorded traffic (no Docker needed)
  .\vitalgate.ps1 start -Mode live   console + Docker test bed + live detector driving the gateway
  .\vitalgate.ps1 stop | status | logs | adduser | requests | approve

Double-click start.cmd, start-live.cmd or stop.cmd for the same thing without typing.
#>
param(
  [ValidateSet("start", "stop", "status", "logs", "adduser", "requests", "approve")][string]$Action = "start",
  [ValidateSet("replay", "live")][string]$Mode = "replay",
  [int]$Port = 8090,
  [double]$Speed = 30,
  [switch]$NoBrowser
)
& (Join-Path $PSScriptRoot "console\vitalgate.ps1") -Action $Action -Mode $Mode -Port $Port -Speed $Speed -NoBrowser:$NoBrowser
