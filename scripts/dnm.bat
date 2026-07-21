@echo off
REM Windows cmd.exe wrapper for scripts\dnm.ps1 — lets you run the commands
REM without opening PowerShell directly, e.g.:  scripts\dnm.bat up
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dnm.ps1" %*
