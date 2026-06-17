# Генерирует version_info.txt для PyInstaller (метаданные Windows .exe)
# Запуск: python build/version_info.py

content = """\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'ООО ВПН-Решения'),
          StringStruct('FileDescription', 'VPN-клиент СКЗИ (ГОСТ Р 34.12-2015)'),
          StringStruct('FileVersion', '1.0.0.0'),
          StringStruct('InternalName', 'VPNGov'),
          StringStruct('LegalCopyright', 'Copyright © 2025 ООО ВПН-Решения'),
          StringStruct('OriginalFilename', 'VPNGov.exe'),
          StringStruct('ProductName', 'VPN-клиент СКЗИ'),
          StringStruct('ProductVersion', '1.0.0'),
        ]
      ),
      StringTable(
        '041904B0',
        [
          StringStruct('CompanyName', 'ООО ВПН-Решения'),
          StringStruct('FileDescription', 'VPN-клиент СКЗИ (ГОСТ Р 34.12-2015)'),
          StringStruct('FileVersion', '1.0.0.0'),
          StringStruct('InternalName', 'VPNGov'),
          StringStruct('LegalCopyright', 'Copyright © 2025 ООО ВПН-Решения'),
          StringStruct('OriginalFilename', 'VPNGov.exe'),
          StringStruct('ProductName', 'VPN-клиент СКЗИ'),
          StringStruct('ProductVersion', '1.0.0'),
        ]
      ),
    ]),
    VarFileInfo([VarStruct('Translation', [0x0409, 0x04B0, 0x0419, 0x04B0])])
  ]
)
"""

import os
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version_info.txt")
with open(out, "w", encoding="utf-8") as f:
    f.write(content)
print(f"Written: {out}")
