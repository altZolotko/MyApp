# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec-файл для VPN-клиента СКЗИ
#
# Сборка:
#   cd <project_root>
#   python build/version_info.py
#   python resources/generate_icon.py
#   pyinstaller build/vpn_gov.spec
#
# Результат: dist/VPNGov/ — директория приложения для инсталлятора
#            dist/VPNGov/VPNGov.exe — исполняемый файл

import os, sys

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

block_cipher = None

# wintun.dll кладётся build.ps1 в vendor\ (или вручную). Бандлим в корень
# приложения, чтобы TUN-адаптер работал без отдельной установки драйвера.
_wintun = os.path.join(ROOT, "vendor", "wintun.dll")
_binaries = []
if os.path.exists(_wintun):
    _binaries.append((_wintun, "."))

a = Analysis(
    [os.path.join(ROOT, "vpn_gui.py")],
    pathex=[ROOT],
    binaries=_binaries,
    datas=[
        (os.path.join(ROOT, "config_bootstrap.json"), "."),
        (os.path.join(ROOT, "pygost"),                "pygost"),
        (os.path.join(ROOT, "gui"),                   "gui"),
        (os.path.join(ROOT, "vpn_core"),              "vpn_core"),
        (os.path.join(ROOT, "utils"),                 "utils"),
    ],
    hiddenimports=[
        # PyQt5
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtGui",
        "PyQt5.QtWidgets",
        "PyQt5.sip",
        # pygost crypto
        "pygost.gost3410",
        "pygost.gost3410_vko",
        "pygost.gost3412",
        "pygost.gost341194",
        "pygost.gost34112012",
        "pygost.gost3413",
        "pygost.gost3414",
        "pygost.gost3415",
        "pygost.gost3416",
        "pygost.mgm",
        "pygost.asn1schemas.oids",
        "pygost.asn1schemas.x509",
        "pygost.asn1schemas.cms",
        # app modules
        "gui.main_window",
        "gui.power_button",
        "gui.server_worker",
        "gui.styles",
        "gui.tunnel_worker",
        "gui.vpn_worker",
        "server",
        "vpn_core.auth",
        "vpn_core.config_manager",
        "vpn_core.protocol",
        "vpn_core.pygost_provider",
        "vpn_core.session",
        "vpn_core.tunnel",
        "utils.app_paths",
        "utils.cert_gen",
        "utils.logger",
        "utils.zeroize",
        # stdlib used at runtime
        "asyncio",
        "logging",
        "logging.handlers",
        "json",
        "struct",
        "threading",
        "ctypes",
        "subprocess",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy", "test"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,       # one-dir mode (лучше для инсталлятора)
    name="VPNGov",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=["vcruntime140.dll", "python3*.dll", "Qt5*.dll"],
    console=False,               # без консольного окна
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "resources", "icon.ico"),
    manifest=os.path.join(ROOT, "resources", "app.manifest"),
    version=os.path.join(ROOT, "build", "version_info.txt"),
    uac_admin=True,              # требовать права администратора при запуске
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=["vcruntime140.dll", "python3*.dll", "Qt5*.dll"],
    name="VPNGov",
)
