@echo off
REM =====================================================================
REM 1_DownloadTools.cmd - BenchToolkit tool fetcher
REM
REM Run this on YOUR internet-connected bench PC, NOT on the customer
REM unit. Downloads Sysinternals Suite (approx 50 MB) from Microsoft
REM and extracts it to Tools\Sysinternals next to this script.
REM
REM Requires Windows 10 1903 or newer (built-in curl.exe and tar.exe).
REM =====================================================================
setlocal
set "BASE=%~dp0"
set "ZIP=%BASE%Tools\SysinternalsSuite.zip"
set "DEST=%BASE%Tools\Sysinternals"

where curl.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: curl.exe not found. This needs Windows 10 1803 or newer.
    exit /b 1
)
where tar.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: tar.exe not found. This needs Windows 10 1903 or newer.
    exit /b 1
)

if not exist "%BASE%Tools" mkdir "%BASE%Tools"
if not exist "%DEST%" mkdir "%DEST%"

echo Downloading Sysinternals Suite from download.sysinternals.com ...
curl.exe -L --fail --retry 3 -o "%ZIP%" https://download.sysinternals.com/files/SysinternalsSuite.zip
if errorlevel 1 (
    echo ERROR: download failed. Check the connection and try again.
    exit /b 1
)

echo Extracting to %DEST% ...
tar.exe -xf "%ZIP%" -C "%DEST%"
if errorlevel 1 (
    echo ERROR: extract failed. The zip may be incomplete - delete it and rerun.
    exit /b 1
)

del "%ZIP%"
echo.
echo Done. Sysinternals tools are in Tools\Sysinternals.
echo Reminder: every Sysinternals tool wants -accepteula on first run, e.g.:
echo     Tools\Sysinternals\autorunsc.exe -accepteula -a *
endlocal
exit /b 0
