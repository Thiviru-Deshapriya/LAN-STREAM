@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: LAN Stream v2 Launcher (Windows Apache Edition)
:: Concurrency Optimized via mod_xsendfile
:: ─────────────────────────────────────────────────────────────────────────────

set PORT=8888
set SCRIPT_DIR=%~dp0

:: ── REQUIRED DIRECTORIES ──────────────────────────────────────────────────────
if not exist "%SCRIPT_DIR%videos\"      mkdir "%SCRIPT_DIR%videos"
if not exist "%SCRIPT_DIR%logs\"        mkdir "%SCRIPT_DIR%logs"
if not exist "%SCRIPT_DIR%data\"        mkdir "%SCRIPT_DIR%data"
if not exist "%SCRIPT_DIR%data\sess\"   mkdir "%SCRIPT_DIR%data\sess"

echo.
echo   ⚡  LAN Stream v2 — Apache Launcher
echo   ─────────────────────────────────────────────────────
echo.

:: 1. Run Apache Setup Script
echo   [+] Configuring XAMPP Apache Virtual Host...
"C:\xampp\php\php.exe" "%SCRIPT_DIR%apache_setup.php"
if %ERRORLEVEL% NEQ 0 (
    echo   [!] Apache setup failed. Check paths or run as Administrator.
    pause
    exit /b 1
)

:: 2. Launch the Session Manager Popup Terminal
echo   [+] Launching Session Manager Terminal...
start "LAN Stream Session Manager" "C:\xampp\php\php.exe" "%SCRIPT_DIR%admin.php"

:: 3. Launch Apache in Background
echo   [+] Starting XAMPP Apache in background...
:: Stop any running instance first to avoid conflict
"C:\xampp\apache\bin\httpd.exe" -k stop -d "C:\xampp\apache" >nul 2>nul
taskkill /IM httpd.exe /F >nul 2>nul

:: Start background server
start "" /B "C:\xampp\apache\bin\httpd.exe" -d "C:\xampp\apache"

echo.
echo   📡  Share this address with devices on your network:
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo       http://%%b:%PORT%/auth.php
    )
)
echo.
echo   ─────────────────────────────────────────────────────
echo   Running Log Monitor below. Press Ctrl+C to Stop.
echo   ─────────────────────────────────────────────────────
echo.

:: 4. Run foreground log watcher
"C:\xampp\php\php.exe" "%SCRIPT_DIR%watcher.php"

:: 5. Clean up Apache on exit
echo.
echo   [-] Stopping Apache web server...
"C:\xampp\apache\bin\httpd.exe" -k stop -d "C:\xampp\apache" >nul 2>nul
taskkill /IM httpd.exe /F >nul 2>nul
echo   [+] Done. Apache stopped.
echo.
pause