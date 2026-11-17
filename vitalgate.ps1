<#
VitalGate launcher: runs the SOC dashboard like an application.

  .\vitalgate.ps1 start              dashboard + replay of recorded traffic (no Docker needed)
  .\vitalgate.ps1 start -Mode live   dashboard + Docker test bed + live detector driving the gateway
  .\vitalgate.ps1 stop               stop everything this launcher started (and the test bed, if it started it)
  .\vitalgate.ps1 status             what is running
  .\vitalgate.ps1 logs               show the last lines of each log
  .\vitalgate.ps1 adduser            add an analyst account / change a password

Double-click start.cmd / stop.cmd for the same thing without typing.
#>
param(
  [ValidateSet("start", "stop", "status", "logs", "adduser")][string]$Action = "start",
  [ValidateSet("replay", "live")][string]$Mode = "replay",
  [int]$Port = 8090,
  [double]$Speed = 30,
  [switch]$NoBrowser
)
$ErrorActionPreference = "Stop"
$Root    = $PSScriptRoot
$Prod    = Join-Path $Root "product"
$Data    = Join-Path $Prod "soc\data"
$Logs    = Join-Path $Data "logs"
$State   = Join-Path $Data "vitalgate.run.json"
$Testbed = Join-Path $Prod "testbed"
$Url     = "http://localhost:$Port"
New-Item -ItemType Directory -Force $Logs | Out-Null

function Say($msg, $color = "Gray") { Write-Host $msg -ForegroundColor $color }
function Listening { [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) }
function Python {
  foreach ($c in "python", "py") { if (Get-Command $c -ErrorAction SilentlyContinue) { return $c } }
  throw "Python was not found. Install Python 3 and tick 'Add python.exe to PATH'."
}
function Ours {   # python processes running our scripts, even ones started by hand
  Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='py.exe'" |
    Where-Object { $_.CommandLine -match 'soc[\\/](server|replay|live)\.py' }
}
function Launch($name, [string[]]$scriptArgs) {
  $py = Python
  $p = Start-Process $py -ArgumentList (@("-u") + $scriptArgs) -WorkingDirectory $Prod -WindowStyle Hidden -PassThru `
         -RedirectStandardOutput (Join-Path $Logs "$name.log") -RedirectStandardError (Join-Path $Logs "$name.err.log")
  Say ("  {0,-8} started (pid {1})" -f $name, $p.Id) "DarkGray"
  return $p.Id
}

switch ($Action) {

  "adduser" {
    $name = Read-Host "Username"
    & (Python) (Join-Path $Prod "soc\server.py") --add-user $name
  }

  "start" {
    Say "`nVitalGate SOC  ($Mode mode)" "Cyan"
    if (Listening) {
      Say "Already running on $Url" "Yellow"
      if (-not $NoBrowser) { Start-Process $Url }
      return
    }
    $py = Python
    # 1. first analyst account (asked here, because the server runs hidden)
    if (-not (Test-Path (Join-Path $Data "users.json"))) {
      Say "No dashboard accounts yet - create the first one." "Yellow"
      $name = Read-Host "Username"
      & $py (Join-Path $Prod "soc\server.py") --add-user $name
      if ($LASTEXITCODE) { throw "Account was not created." }
    }
    $run = @{ mode = $Mode; port = $Port; started = (Get-Date).ToString("s"); pids = @(); docker = $false }

    # 2. live mode needs the Docker test bed
    if ($Mode -eq "live") {
      if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker is not installed or not on PATH." }
      docker info *> $null
      if ($LASTEXITCODE) { throw "Docker Desktop is not running. Start it and try again." }
      Say "Starting the test bed (first time can take a few minutes)..."
      Push-Location $Testbed
      try { docker compose up -d --build *> (Join-Path $Logs "docker.log"); if ($LASTEXITCODE) { throw "docker compose failed - see $Logs\docker.log" } }
      finally { Pop-Location }
      $run.docker = $true
    }

    # 3. dashboard server
    $run.pids += Launch "server" @("soc/server.py", "--port", "$Port")
    $t = 0; while (-not (Listening) -and $t -lt 40) { Start-Sleep -Milliseconds 250; $t++ }
    if (-not (Listening)) {
      Say "The dashboard did not start. Last log lines:" "Red"
      Get-Content (Join-Path $Logs "server.err.log"), (Join-Path $Logs "server.log") -Tail 15 -ErrorAction SilentlyContinue
      return
    }

    # 4. data feed
    if ($Mode -eq "live") { $run.pids += Launch "live"   @("soc/live.py") }
    else                  { $run.pids += Launch "replay" @("soc/replay.py", "--speed", "$Speed") }

    $run | ConvertTo-Json | Set-Content $State -Encoding UTF8
    Say "`nRunning:  $Url" "Green"
    Say "Stop with:  .\vitalgate.ps1 stop   (or double-click stop.cmd)" "DarkGray"
    Say "Logs in:    $Logs`n" "DarkGray"
    if (-not $NoBrowser) { Start-Process $Url }
  }

  "stop" {
    $run = if (Test-Path $State) { Get-Content $State -Raw | ConvertFrom-Json } else { $null }
    $procs = @(Ours)
    if ($procs.Count) {
      $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                                Say ("  stopped {0} (pid {1})" -f ($_.CommandLine -replace '.*soc[\\/](\w+)\.py.*', '$1'), $_.ProcessId) "DarkGray" }
    } else { Say "No VitalGate processes were running." }
    if ($run -and $run.docker) {
      Say "Stopping the test bed..."
      Push-Location $Testbed; try { docker compose down *> $null } finally { Pop-Location }
    }
    Remove-Item $State -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Data "live.lock") -ErrorAction SilentlyContinue
    Say "VitalGate stopped." "Green"
  }

  "status" {
    $run = if (Test-Path $State) { Get-Content $State -Raw | ConvertFrom-Json } else { $null }
    if (Listening) { Say "Dashboard:  running on $Url" "Green" } else { Say "Dashboard:  stopped" "Yellow" }
    $procs = @(Ours)
    foreach ($p in $procs) { Say ("  {0,-7} pid {1}" -f ($p.CommandLine -replace '.*soc[\\/](\w+)\.py.*', '$1'), $p.ProcessId) }
    if ($run) { Say "Mode: $($run.mode), started $($run.started)" "DarkGray" }
    if ($run -and $run.docker) { Push-Location $Testbed; try { docker compose ps } finally { Pop-Location } }
  }

  "logs" {
    Get-ChildItem $Logs -Filter *.log | Where-Object Length -gt 0 | ForEach-Object {
      Say "`n== $($_.Name) ==" "Cyan"; Get-Content $_.FullName -Tail 12
    }
  }
}
