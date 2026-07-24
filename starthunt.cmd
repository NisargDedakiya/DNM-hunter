@echo off
REM ===========================================================================
REM starthunt.cmd - Windows one-command launcher for the whole DNM-Hunter stack.
REM
REM The orchestration lives in the bash script `starthunt` (it drives Docker
REM Compose). On Windows that runs under Git Bash or WSL, both of which ship
REM with Docker Desktop. This wrapper just finds bash and hands off, so you can
REM run `starthunt` (or `starthunt dev`, `starthunt stop`, ...) from CMD or
REM PowerShell exactly like on Linux/macOS.
REM ===========================================================================
setlocal
cd /d "%~dp0"

where bash >nul 2>&1
if %errorlevel%==0 (
  bash ./starthunt %*
  goto :eof
)

REM No bash on PATH - try WSL.
where wsl >nul 2>&1
if %errorlevel%==0 (
  wsl ./starthunt %*
  goto :eof
)

echo [error] Could not find "bash" or "wsl".
echo         Install Docker Desktop (which includes WSL2), or Git for Windows
echo         (which includes Git Bash), then run:  starthunt
exit /b 1
