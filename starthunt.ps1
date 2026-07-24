<#
  starthunt.ps1 - Windows PowerShell one-command launcher for the whole
  DNM-Hunter stack.

  The orchestration lives in the bash script `starthunt` (it drives Docker
  Compose). On Windows that runs under Git Bash or WSL, both of which ship with
  Docker Desktop. This wrapper finds one of them and hands off, so from
  PowerShell you can run:

      .\starthunt.ps1            # start everything
      .\starthunt.ps1 dev        # dev mode (hot-reload)
      .\starthunt.ps1 stop       # stop (data kept)
      .\starthunt.ps1 status     # what's running
      .\starthunt.ps1 logs       # tail logs
      .\starthunt.ps1 help

  (If PowerShell blocks the script with an execution-policy error, run it once as:
      powershell -ExecutionPolicy Bypass -File .\starthunt.ps1  )
#>

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

# Prefer Git Bash (`bash` on PATH), then WSL.
$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash) {
    & $bash.Source './starthunt' @args
    exit $LASTEXITCODE
}

$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if ($wsl) {
    & $wsl.Source './starthunt' @args
    exit $LASTEXITCODE
}

Write-Host "[error] Could not find 'bash' or 'wsl'." -ForegroundColor Red
Write-Host "        DNM-Hunter runs on Docker Desktop, which includes WSL2."
Write-Host "        Install one of these, then re-run  .\starthunt.ps1 :"
Write-Host "          - Docker Desktop with the WSL2 backend (recommended), or"
Write-Host "          - Git for Windows (provides Git Bash)."
exit 1
