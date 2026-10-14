@echo off
rem Sabel Threat Detection launcher: starts the 64-bit Windows PowerShell with a process-only
rem execution-policy bypass (does not change your system's PowerShell policy).
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Sabel.ps1" %*
