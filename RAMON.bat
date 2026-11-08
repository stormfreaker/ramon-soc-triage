@echo off
title RAMON - SOC Triage
cd /d "%~dp0"
set STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Ramon.vbs

:menu
cls
echo.
echo   ============  RAMON - SOC Triage  ============
echo.
py ramon_status.py --short
echo.
echo   1  Start RAMON
echo   2  Stop RAMON
echo   3  Health check (is everything working?)
echo   4  Open Splunk dashboard
echo   5  Open activity log
echo   6  Autostart at login: ON
echo   7  Autostart at login: OFF
echo   0  Close this window
echo.
choice /c 12345670 /n /m "  Choose a number: "
if errorlevel 8 goto :eof
if errorlevel 7 goto auto_off
if errorlevel 6 goto auto_on
if errorlevel 5 goto log
if errorlevel 4 goto dash
if errorlevel 3 goto health
if errorlevel 2 goto stop
if errorlevel 1 goto start

:start
wscript "%~dp0start_ramon.vbs"
echo.
echo   Starting... RAMON now runs in the background. You can close this window.
timeout /t 4 >nul
goto menu

:stop
echo.
py ramon_status.py --stop
timeout /t 3 >nul
goto menu

:health
py ramon_status.py --health
echo.
pause
goto menu

:dash
start "" "http://localhost:8000/en-GB/app/search/ramon"
goto menu

:log
start "" notepad "%~dp0service.log"
goto menu

:auto_on
:: write a small launcher with this folder's path into the Startup folder
> "%STARTUP%" echo Set sh = CreateObject("WScript.Shell")
>> "%STARTUP%" echo sh.CurrentDirectory = "%~dp0"
>> "%STARTUP%" echo sh.Run "pyw ""%~dp0ramon_service.py""", 0, False
echo.
echo   Autostart is ON: RAMON will start every time you log in to Windows.
timeout /t 3 >nul
goto menu

:auto_off
if exist "%STARTUP%" del "%STARTUP%"
echo.
echo   Autostart is OFF.
timeout /t 3 >nul
goto menu
