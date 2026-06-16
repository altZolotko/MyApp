@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title VPN-klient SKZI (GOST) - zapusk
cd /d "%~dp0"

echo ============================================================
echo   VPN-klient SKZI (GOST) - avtomaticheskiy zapusk
echo ============================================================
echo.

REM --- Shag 1: poisk rabotayushchego Python ---
REM Vazhno: na Windows komandy "python"/"py" mogut byt "zaglushkami"
REM (App Execution Alias), kotorye nichego ne ustanavlivayut, a prosto
REM otkryvayut Microsoft Store. "where" ih vse ravno nahodit, poetomu
REM dopolnitelno proveryaem, chto --version vozvrashchaet nastoyashchiy
REM nomer versii, a pip rabotaet.
set "PY="
call :TryPython py
if not defined PY call :TryPython python
if not defined PY call :TryPython python3

if not defined PY (
    echo [OSHIBKA] Rabotayushchiy Python ne nayden.
    echo.
    echo Vozmozhno, eto "zaglushka" Microsoft Store vmesto nastoyashchego
    echo Python. Ustanovite Python 3.10 ili novee s sayta:
    echo     https://www.python.org/downloads/
    echo VAZHNO: pri ustanovke postavte galochku "Add Python to PATH".
    echo.
    echo Esli Python uzhe ustanovlen, no oshibka povtoryaetsya - otklyuchite
    echo zaglushki: Parametry - Prilozheniya - Psevdonimy vypolneniya
    echo prilozheniy - vyklyuchite "python.exe" i "python3.exe".
    echo.
    pause
    exit /b 1
)
echo [1/4] Python nayden: %PY%
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
exit /b 0

REM ============================================================
REM Proverka odnogo kandidata na rol' "nastoyashchego" Python:
REM   1) komanda dolzhna nayitis' v PATH (where)
REM   2) "--version" dolzhen vyvodit' stroku vida "Python 3.x.y"
REM      (zaglushka Windows Store vyvodit sovsem drugoy tekst)
REM   3) "-m pip --version" dolzhen rabotat'
REM Pri uspehe ustanavlivaet PY=<kandidat>.
REM ============================================================
:TryPython
set "CANDIDATE=%~1"
where %CANDIDATE% >nul 2>nul
if errorlevel 1 goto :eof

set "VEROUT="
for /f "delims=" %%v in ('%CANDIDATE% --version 2^>^&1') do (
    if not defined VEROUT set "VEROUT=%%v"
)
echo !VEROUT! | findstr /r /c:"^Python [0-9]" >nul 2>nul
if errorlevel 1 goto :eof

%CANDIDATE% -m pip --version >nul 2>nul
if errorlevel 1 goto :eof

set "PY=%CANDIDATE%"
goto :eof
