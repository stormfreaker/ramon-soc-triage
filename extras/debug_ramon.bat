@echo off
cd /d "%~dp0.."
echo === Checking Python launchers ===
where py
where pyw
echo.
echo === Checking autostart ===
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Ramon.vbs" (echo Autostart installed) else (echo Autostart NOT installed)
echo.
echo === Running Ramon visibly - leave this open for 3 minutes, then close it ===
py ramon_service.py
pause
