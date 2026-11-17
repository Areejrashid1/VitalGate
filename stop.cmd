@echo off
rem Double-click to stop VitalGate
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0vitalgate.ps1" stop
pause
