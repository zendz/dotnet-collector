@echo off
setlocal
set "WDC_DIR=%~dp0"
echo [WDC] Launching Windows .NET Discovery Collector version 1.1.2...
echo [WDC] Created by gosft (Thailand) co., ltd.
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo [FATAL] powershell.exe was not found.
  exit /b 3
)

rem Bypass applies only to this process. It does not change machine policy.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%WDC_DIR%wdc.ps1" %*
exit /b %ERRORLEVEL%
