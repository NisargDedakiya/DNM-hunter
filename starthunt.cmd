@echo off
REM ===========================================================================
REM starthunt.cmd - Windows CMD launcher for the whole DNM-Hunter stack.
REM Hands off to the native PowerShell launcher (no bash / WSL needed).
REM   Usage:  starthunt  |  starthunt dev  |  starthunt stop  |  starthunt status
REM ===========================================================================
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0starthunt.ps1" %*
exit /b %errorlevel%
