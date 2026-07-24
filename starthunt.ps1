<#
  starthunt.ps1 — native Windows PowerShell launcher for the whole DNM-Hunter
  stack. Drives Docker Compose directly (NO bash / WSL / Git Bash required), so it
  works on a plain Windows + Docker Desktop machine.

  Usage (from this folder, in PowerShell):
      .\starthunt.ps1              start everything (installs on first run)
      .\starthunt.ps1 dev          dev mode (hot-reload)
      .\starthunt.ps1 stop         stop the stack (data kept)
      .\starthunt.ps1 status       what's running
      .\starthunt.ps1 logs         tail logs   (or: .\starthunt.ps1 logs webapp)
      .\starthunt.ps1 restart
      .\starthunt.ps1 update       rebuild + restart
      .\starthunt.ps1 help

  If PowerShell blocks the script:
      powershell -ExecutionPolicy Bypass -File .\starthunt.ps1
#>
[CmdletBinding()]
param([Parameter(Position = 0)] [string] $Command = 'up',
      [Parameter(Position = 1)] [string] $Arg1)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

# Core always-on services (matches nisarghunter.sh CORE_SERVICES). We list them
# explicitly so a plain "compose up" does NOT also start the heavy GVM stack.
$CORE = @('postgres', 'neo4j', 'docker-broker', 'recon-orchestrator', 'kali-sandbox', 'agent', 'webapp')
$WEBAPP_PORT = if ($env:WEBAPP_PORT) { $env:WEBAPP_PORT } else { '3000' }
$AGENT_PORT  = if ($env:AGENT_PORT)  { $env:AGENT_PORT }  else { '8090' }
$EnvFile = Join-Path $PSScriptRoot '.env'

function Info($m) { Write-Host "[starthunt] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[ok] $m"        -ForegroundColor Green }
function Warn($m) { Write-Host "[warn] $m"      -ForegroundColor Yellow }
function Die($m)  { Write-Host "[error] $m"     -ForegroundColor Red; exit 1 }

function New-Hex([int]$bytes) {
  $b = New-Object 'byte[]' $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ($b | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Banner {
  Write-Host ""
  Write-Host "  DNM-HUNTER" -ForegroundColor Red
  Write-Host "  AI-powered vulnerability research platform" -ForegroundColor DarkGray
  Write-Host ""
}

function Preflight {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die "Docker is not installed. Install Docker Desktop for Windows, then re-run."
  }
  & docker info *> $null
  if ($LASTEXITCODE -ne 0) {
    Die "The Docker daemon isn't running. Start Docker Desktop (whale icon in the tray), wait for 'Engine running', then re-run."
  }
  & docker compose version *> $null
  if ($LASTEXITCODE -ne 0) { Die "'docker compose' (v2) is required. Update Docker Desktop." }
}

function Test-EnvHas([string]$var) {
  if (-not (Test-Path $EnvFile)) { return $false }
  return @(Get-Content $EnvFile) -match "^$var="
}
function Add-EnvLine([string]$line) { Add-Content -Path $EnvFile -Value $line -Encoding Ascii }

function Ensure-Env {
  if (-not (Test-Path $EnvFile)) {
    $example = Join-Path $PSScriptRoot '.env.example'
    if (Test-Path $example) {
      Copy-Item $example $EnvFile
      Warn "No .env found — created one from .env.example (defaults are fine for local use)."
    } else {
      New-Item -ItemType File -Path $EnvFile | Out-Null
    }
  }
}

function Ensure-AuthSecrets {
  foreach ($v in @('AUTH_SECRET', 'INTERNAL_API_KEY', 'ORCHESTRATOR_API_KEY', 'MCP_AUTH_TOKEN', 'CREDENTIAL_VAULT_ENCRYPTION_KEY')) {
    if (-not (Test-EnvHas $v)) { Add-EnvLine "$v=$(New-Hex 32)"; Info "Generated $v" }
  }
}

function Volume-Exists([string]$suffix) {
  $vols = & docker volume ls --format '{{.Name}}' 2>$null
  return @($vols) -match "$suffix$"
}
function Ensure-DbSecrets {
  foreach ($spec in @(@{v='POSTGRES_PASSWORD'; s='postgres_data'}, @{v='NEO4J_PASSWORD'; s='neo4j_data'})) {
    if (Test-EnvHas $spec.v) { continue }
    if (Volume-Exists $spec.s) {
      Warn "$($spec.v) is unset but its data volume already exists — leaving the existing DB password as-is."
    } else {
      Add-EnvLine "$($spec.v)=$(New-Hex 24)"; Info "Generated strong $($spec.v) (fresh install)"
    }
  }
}

function Wait-Web {
  Info "Waiting for the web app on http://localhost:$WEBAPP_PORT ..."
  for ($i = 0; $i -lt 90; $i++) {
    try {
      Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://localhost:$WEBAPP_PORT" *> $null
      return $true
    } catch { Start-Sleep -Seconds 2 }
  }
  return $false
}

function Ensure-Admin {
  # Give the webapp a moment; check-admin.mjs prints the admin count.
  $has = ''
  try { $has = (& docker compose exec -T webapp node scripts/check-admin.mjs 2>$null) -join '' } catch { }
  $has = "$has".Trim()
  if ($has -eq '0' -or $has -eq '') {
    Write-Host ""
    Warn "No admin user found — let's create one."
    $name  = Read-Host "  Admin name"
    $email = Read-Host "  Admin email"
    while ($true) {
      $p1 = Read-Host "  Admin password" -AsSecureString
      $p2 = Read-Host "  Confirm password" -AsSecureString
      $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
      $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
      if ($s1 -eq $s2) { break }
      Warn "Passwords do not match. Try again."
    }
    & docker compose exec -T -e "ADMIN_NAME=$name" -e "ADMIN_EMAIL=$email" -e "ADMIN_PASSWORD=$s1" webapp node scripts/create-admin.mjs
    Ok "Admin user created."
  }
}

function Print-Ready {
  Write-Host ""
  Ok "DNM-Hunter is up."
  Write-Host "   Web app   ->  http://localhost:$WEBAPP_PORT" -ForegroundColor Cyan
  Write-Host "   AI agent  ->  http://localhost:$AGENT_PORT"
  Write-Host ""
  Write-Host "   Logs: .\starthunt.ps1 logs     Status: .\starthunt.ps1 status     Stop: .\starthunt.ps1 stop"
  Write-Host ""
}

function Compose-Up([switch]$Build, [string[]]$Files) {
  $a = @('compose')
  foreach ($f in $Files) { $a += @('-f', $f) }
  $a += @('up', '-d')
  if ($Build) { $a += '--build' }
  $a += $CORE
  & docker @a
}

function Start-Stack([switch]$Build) {
  Ensure-Env; Ensure-AuthSecrets; Ensure-DbSecrets
  $first = -not @(& docker ps -a --filter 'name=nisarghunter-' -q 2>$null)
  if ($first) { Info "First run — building images and starting the full stack (this can take a while)…" }
  else        { Info "Starting the full stack…" }
  Compose-Up -Build:$Build
  if ($LASTEXITCODE -ne 0) { Die "docker compose failed — see the output above." }
  if (Wait-Web) { Ensure-Admin; Print-Ready }
  else { Warn "Web app didn't answer yet — it may still be building. Check: .\starthunt.ps1 logs webapp"; Print-Ready }
}

switch ($Command.ToLower()) {
  { $_ -in @('up', 'start', '') } { Banner; Preflight; Start-Stack }
  'dev' {
    Banner; Preflight; Ensure-Env; Ensure-AuthSecrets; Ensure-DbSecrets
    Info "Starting in dev mode (hot-reload)…"
    Compose-Up -Files @('docker-compose.yml', 'docker-compose.dev.yml')
    if (Wait-Web) { Ensure-Admin; Print-Ready } else { Print-Ready }
  }
  { $_ -in @('stop', 'down') } { Preflight; Info "Stopping (data kept)…"; & docker compose down; Ok "Stopped." }
  'restart' { Preflight; & docker compose down; Banner; Start-Stack }
  'status'  { Preflight; & docker compose ps }
  'logs'    { Preflight; if ($Arg1) { & docker compose logs -f $Arg1 } else { & docker compose logs -f } }
  'update'  { Banner; Preflight; Info "Rebuilding + restarting…"; Start-Stack -Build }
  'reinstall' { Banner; Preflight; Start-Stack -Build }
  { $_ -in @('help', '-h', '--help') } { Banner; Get-Help $PSCommandPath -Detailed | Out-Host }
  default { Die "Unknown command: $Command  (try: .\starthunt.ps1 help)" }
}
