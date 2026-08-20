@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: LAN Stream v2 Launcher (Standalone PHP Edition)
:: Use this if XAMPP is NOT installed. Requires only php.exe
:: ─────────────────────────────────────────────────────────────────────────────

set PORT=8888
set SCRIPT_DIR=%~dp0

:: Check if PHP is available
php -v >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] PHP is not installed or not in your system PATH.
    echo Please download standalone PHP from windows.php.net, extract it,
    echo and add it to your System Environment Variables.
    pause
    exit /b 1
)

:: Ensure directories exist
if not exist "%SCRIPT_DIR%videos\"      mkdir "%SCRIPT_DIR%videos"
if not exist "%SCRIPT_DIR%logs\"        mkdir "%SCRIPT_DIR%logs"
if not exist "%SCRIPT_DIR%data\"        mkdir "%SCRIPT_DIR%data"
if not exist "%SCRIPT_DIR%data\sess\"   mkdir "%SCRIPT_DIR%data\sess"

:: Enable concurrent streaming workers for PHP built-in server (PHP 7.4+)
set PHP_CLI_SERVER_WORKERS=4

echo.
echo   ⚡  LAN Stream v2 — Standalone PHP Launcher
echo   ─────────────────────────────────────────────────────
echo.
echo   [+] Launching Session Manager Terminal...
start "LAN Stream Session Manager" php "%SCRIPT_DIR%admin.php"

echo.
echo   📡  Share this address with devices on your network:
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo       http://%%b:%PORT%/auth.php
    )
)
echo.
echo   ⚙  Workers  : %PHP_CLI_SERVER_WORKERS% concurrent streams supported
echo   ─────────────────────────────────────────────────────
echo   Running Log Monitor below. Press Ctrl+C to Stop.
echo   ─────────────────────────────────────────────────────
echo.

:: Start the background log watcher
start /B "Log Watcher" php "%SCRIPT_DIR%watcher.php"

:: Start the PHP Built-in Server
php -S 0.0.0.0:%PORT% -t "%SCRIPT_DIR%"

pause
