@echo off
cd /d "%~dp0.."
echo Running Ramon on up to 10 alerts from Splunk...
py ramon.py --max 10
echo.
echo Verdicts are in Splunk (index=ramon) and results.csv
pause
