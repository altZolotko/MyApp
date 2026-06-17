<#
.SYNOPSIS
    Сборка VPN-клиента СКЗИ в standalone Windows-приложение.

.DESCRIPTION
    Полный pipeline:
      1. Генерация иконки (Pillow)
      2. Генерация version_info.txt
      3. PyInstaller → dist\VPNGov\
      4. Inno Setup → dist\VPNGov_Setup_1.0.0.exe   (если iscc доступен)
      5. MSIX → dist\VPNGov_1.0.0.msix               (если makeappx доступен)

.PARAMETER SkipIcon
    Пропустить генерацию иконки (если icon.ico уже есть).

.PARAMETER SkipInstaller
    Пропустить шаг Inno Setup.

.PARAMETER SkipMsix
    Пропустить шаг MSIX.

.PARAMETER Sign
    Подписать exe/msix после сборки (нужен signtool и сертификат).

.EXAMPLE
    .\build\build.ps1
    .\build\build.ps1 -SkipIcon -SkipMsix
    .\build\build.ps1 -Sign
#>

[CmdletBinding()]
param(
    [switch]$SkipIcon,
    [switch]$SkipInstaller,
    [switch]$SkipMsix,
    [switch]$Sign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Цвета вывода ──────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "    WARN: $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "    FAIL: $msg" -ForegroundColor Red; throw $msg }

# ── Пути ──────────────────────────────────────────────────────────────────────
$Root      = Split-Path $PSScriptRoot -Parent   # project root
$BuildDir  = $PSScriptRoot                       # build\
$DistDir   = Join-Path $Root "dist"
$IconPath  = Join-Path $Root "resources\icon.ico"
$SpecFile  = Join-Path $BuildDir "vpn_gov.spec"
$IssFile   = Join-Path $BuildDir "setup.iss"
$AppxFile  = Join-Path $BuildDir "AppxManifest.xml"
$MsixDir   = Join-Path $DistDir "VPNGov_msix"
$MsixOut   = Join-Path $DistDir "VPNGov_1.0.0.msix"
$AppVer    = "1.0.0"

Push-Location $Root

try {

# ── 1. Иконка ─────────────────────────────────────────────────────────────────
Write-Step "Шаг 1/5: Генерация иконки"
if ($SkipIcon -and (Test-Path $IconPath)) {
    Write-Warn "Пропускаем (icon.ico уже существует)"
} else {
    python resources\generate_icon.py
    if (-not (Test-Path $IconPath)) { Write-Fail "icon.ico не создан" }
    Write-OK "resources\icon.ico создан"
}

# ── 2. version_info.txt ───────────────────────────────────────────────────────
Write-Step "Шаг 2/5: Генерация version_info.txt"
python build\version_info.py
$VerFile = Join-Path $BuildDir "version_info.txt"
if (-not (Test-Path $VerFile)) { Write-Fail "version_info.txt не создан" }
Write-OK "build\version_info.txt создан"

# ── 3. PyInstaller ────────────────────────────────────────────────────────────
Write-Step "Шаг 3/5: PyInstaller"
$PyI = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $PyI) { Write-Fail "pyinstaller не найден в PATH. Установите: pip install pyinstaller" }

# Очищаем предыдущую сборку
if (Test-Path (Join-Path $DistDir "VPNGov")) {
    Remove-Item (Join-Path $DistDir "VPNGov") -Recurse -Force
    Write-Warn "Удалена предыдущая сборка dist\VPNGov\"
}

pyinstaller $SpecFile --noconfirm
$ExePath = Join-Path $DistDir "VPNGov\VPNGov.exe"
if (-not (Test-Path $ExePath)) { Write-Fail "VPNGov.exe не создан после PyInstaller" }
Write-OK "dist\VPNGov\VPNGov.exe создан"

# ── Подпись exe (опционально) ─────────────────────────────────────────────────
if ($Sign) {
    $SignTool = Get-Command signtool -ErrorAction SilentlyContinue
    if ($SignTool) {
        Write-Step "Подпись VPNGov.exe"
        signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $ExePath
        Write-OK "Подписан: $ExePath"
    } else {
        Write-Warn "signtool не найден — подпись пропущена"
    }
}

# ── 4. Inno Setup ─────────────────────────────────────────────────────────────
Write-Step "Шаг 4/5: Inno Setup → установщик .exe"
if ($SkipInstaller) {
    Write-Warn "Пропускаем (--SkipInstaller)"
} else {
    $Iscc = Get-Command iscc -ErrorAction SilentlyContinue
    if (-not $Iscc) {
        # Ищем в стандартном месте
        $IsccDefault = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
        if (Test-Path $IsccDefault) {
            $Iscc = $IsccDefault
        } else {
            Write-Warn "iscc не найден — пропускаем инсталлятор"
            Write-Warn "Скачайте: https://jrsoftware.org/isinfo.php"
        }
    }
    if ($Iscc) {
        & $Iscc $IssFile
        $SetupExe = Join-Path $DistDir "VPNGov_Setup_$AppVer.exe"
        if (Test-Path $SetupExe) {
            Write-OK "dist\VPNGov_Setup_$AppVer.exe создан"
        } else {
            Write-Warn "Установщик не найден после iscc — проверьте вывод выше"
        }
    }
}

# ── 5. MSIX ───────────────────────────────────────────────────────────────────
Write-Step "Шаг 5/5: MSIX → Microsoft Store"
if ($SkipMsix) {
    Write-Warn "Пропускаем (--SkipMsix)"
} else {
    $MakeAppx = Get-Command makeappx -ErrorAction SilentlyContinue
    if (-not $MakeAppx) {
        # Windows SDK обычно в Program Files (x86)
        $Candidates = @(
            "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\makeappx.exe",
            "C:\Program Files (x86)\Windows Kits\10\bin\x64\makeappx.exe"
        )
        foreach ($c in $Candidates) {
            if (Test-Path $c) { $MakeAppx = $c; break }
        }
    }

    if (-not $MakeAppx) {
        Write-Warn "makeappx не найден — пропускаем MSIX"
        Write-Warn "Установите Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/"
    } else {
        # Готовим папку MSIX: копируем dist\VPNGov\ + манифест + Assets
        if (Test-Path $MsixDir) { Remove-Item $MsixDir -Recurse -Force }
        New-Item -ItemType Directory -Path $MsixDir | Out-Null
        Copy-Item (Join-Path $DistDir "VPNGov\*") $MsixDir -Recurse
        Copy-Item $AppxFile (Join-Path $MsixDir "AppxManifest.xml") -Force

        # Assets: если папка есть — копируем; иначе предупреждение
        $AssetsDir = Join-Path $Root "resources\Assets"
        if (Test-Path $AssetsDir) {
            Copy-Item $AssetsDir (Join-Path $MsixDir "Assets") -Recurse -Force
        } else {
            Write-Warn "resources\Assets\ не найдена — Store-иконки отсутствуют в MSIX"
            Write-Warn "Создайте PNG-иконки согласно требованиям Store перед публикацией"
        }

        if (Test-Path $MsixOut) { Remove-Item $MsixOut -Force }
        & $MakeAppx pack /d $MsixDir /p $MsixOut /nv
        if (Test-Path $MsixOut) {
            Write-OK "dist\VPNGov_1.0.0.msix создан"
        } else {
            Write-Warn "MSIX не создан — проверьте вывод makeappx выше"
        }

        # Подпись MSIX (опционально)
        if ($Sign -and (Test-Path $MsixOut)) {
            $SignTool = Get-Command signtool -ErrorAction SilentlyContinue
            if ($SignTool) {
                signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $MsixOut
                Write-OK "Подписан: $MsixOut"
            } else {
                Write-Warn "signtool не найден — MSIX не подписан"
            }
        }
    }
}

# ── Итог ──────────────────────────────────────────────────────────────────────
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Сборка завершена!" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
$Artifacts = @(
    (Join-Path $DistDir "VPNGov\VPNGov.exe"),
    (Join-Path $DistDir "VPNGov_Setup_$AppVer.exe"),
    $MsixOut
)
foreach ($a in $Artifacts) {
    if (Test-Path $a) {
        $size = (Get-Item $a).Length / 1MB
        Write-Host ("  {0,-45} {1:F1} MB" -f (Resolve-Path $a -Relative), $size) -ForegroundColor Green
    }
}
Write-Host ""

} finally {
    Pop-Location
}
