@echo off
chcp 65001 >nul
title VPN-klient SKZI (GOST) - zapusk
cd /d "%~dp0"

echo ============================================================
echo   VPN-klient SKZI (GOST) - avtomaticheskiy zapusk
echo ============================================================
echo.

REM --- Shag 1: poisk Python ---
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY ( where python >nul 2>nul && set "PY=python" )
if not defined PY (
    echo [OSHIBKA] Python ne nayden.
    echo.
    echo Ustanovite Python 3.10 ili novee s sayta:
    echo     https://www.python.org/downloads/
    echo VAZHNO: pri ustanovke postavte galochku "Add Python to PATH".
    echo.
    pause
    exit /b 1
)
echo [1/4] Python nayden:
%PY% --version
echo.

REM --- Shag 2: ustanovka zavisimostey ---
echo [2/4] Ustanovka zavisimostey (pygost, PyQt5)...
%PY% -m pip install --upgrade pip --quiet --disable-pip-version-check
%PY% -m pip install --quiet --disable-pip-version-check -r requirements.txt
if %errorlevel% neq 0 (
    echo [OSHIBKA] Ne udalos ustanovit zavisimosti.
    pause
    exit /b 1
)
echo     Gotovo.
echo.

REM --- Shag 3: generatsiya sertifikatov ---
echo [3/4] Proverka sertifikatov...
if not exist "certs\client.der" (
    echo     Generatsiya testovyh sertifikatov...
    %PY% -m utils.cert_gen
) else (
    echo     Sertifikaty uzhe sushchestvuyut.
)
echo.

REM --- Shag 4: zapusk servera i interfeysa ---
echo [4/4] Zapusk testovogo servera i interfeysa...
start "VPN Server (NE ZAKRYVAT)" %PY% server.py
echo     Server zapushchen v otdelnom okne.

REM Pauza, chtoby server uspel startovat
timeout /t 2 /nobreak >nul

echo     Otkrytie graficheskogo interfeysa...
echo.
%PY% vpn_gui.py

echo.
echo Rabota zavershena. Mozhno zakryt okno servera.
pause
