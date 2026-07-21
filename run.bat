@echo off
title Advanced Port Scanner 2.0
color 0B
cls

:menu
cls
echo ============================================================
echo           🔍 Advanced Port Scanner 2.0 Launcher
echo ============================================================
echo.
echo   [1] Launch Modern Dark GUI (Graphical Interface)
echo   [2] Quick Terminal Scan (Localhost 127.0.0.1: Ports 1-1024)
echo   [3] Custom Terminal Scan (Enter Target IP & Ports)
echo   [4] Exit
echo.
echo ============================================================
set /p choice="Select an option [1-4]: "

if "%choice%"=="1" goto gui
if "%choice%"=="2" goto quick
if "%choice%"=="3" goto custom
if "%choice%"=="4" goto end

echo.
echo [!] Invalid option. Please select 1, 2, 3, or 4.
timeout /t 2 >nul
goto menu

:gui
cls
echo [*] Launching Graphical UI...
python port_scanner.py
goto end

:quick
cls
echo [*] Running Quick Terminal Scan on 127.0.0.1 (Ports 1-1024)...
echo.
python index.py -t 127.0.0.1 -p 1-1024 -b
echo.
echo [x] Scan finished. Press any key to return to menu.
pause >nul
goto menu

:custom
cls
echo ============================================================
echo                  Custom Terminal Port Scan
echo ============================================================
echo.
set /p target="Enter Target IP or Domain (default: 127.0.0.1): "
if "%target%"=="" set target=127.0.0.1

set /p ports="Enter Port Range or List (default: 1-1024): "
if "%ports%"=="" set ports=1-1024

echo.
echo [*] Running Scan on %target% (Ports: %ports%)...
echo.
python index.py -t %target% -p %ports% -b
echo.
echo [x] Scan finished. Press any key to return to menu.
pause >nul
goto menu

:end
exit
