; Inno Setup 6+ скрипт для VPN-клиента СКЗИ
; Создаёт полноценный установщик Windows с ярлыком, UAC и деинсталлятором.
;
; Предварительно: собрать PyInstaller bundle (dist\VPNGov\)
; Инструмент: https://jrsoftware.org/isinfo.php  (Inno Setup 6.x)
; Сборка: iscc build\setup.iss
; Результат: dist\VPNGov_Setup_1.0.0.exe

#define AppName        "VPN-клиент СКЗИ"
#define AppNameEn      "VPNGov"
#define AppVersion     "1.0.0"
#define AppPublisher   "ООО ВПН-Решения"
#define AppURL         "https://vpngov.example.ru"
#define AppExeName     "VPNGov.exe"
#define AppGUID        "{{A7B3C2D1-1234-5678-ABCD-EF0123456789}"
#define DistDir        "..\dist\VPNGov"

[Setup]
AppId={#AppGUID}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppNameEn}
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=VPNGov_Setup_{#AppVersion}
SetupIconFile=..\resources\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
ShowLanguageDialog=auto
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
CloseApplications=force
RestartApplications=no
; Для подписи кода раскомментируйте:
; SignTool=signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $f

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "{cm:CreateDesktopIcon}";   GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon";   Description: "Запускать при старте Windows"; GroupDescription: "Автозапуск:"; Flags: unchecked

[Files]
; Основные файлы приложения из PyInstaller bundle
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Драйвер WinTun (если есть рядом со скриптом сборки)
; Source: "..\vendor\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion; Check: IsWin64

[Icons]
Name: "{group}\{#AppName}";                Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Удалить {#AppName}";        Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";        Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; Автозапуск (только если выбрана задача)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "{#AppNameEn}"; \
  ValueData: """{app}\{#AppExeName}"""; \
  Tasks: startupicon; Flags: uninsdeletevalue

[Run]
; После установки предложить запустить приложение
Filename: "{app}\{#AppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; При деинсталляции убить процесс если запущен
Filename: "taskkill.exe"; Parameters: "/F /IM {#AppExeName}"; Flags: runhidden; RunOnceId: "KillApp"

[UninstallDelete]
; Удалять только пользовательский кеш, НЕ трогать сертификаты и конфиги
Type: filesandordirs; Name: "{localappdata}\VPNGov\Logs"

[Code]
// Проверяем наличие Windows 10 1903+ (необходимо для WinTun 0.14+)
function InitializeSetup(): Boolean;
var
  ver: Cardinal;
begin
  Result := True;
  if not RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentMajorVersionNumber', ver) then
  begin
    MsgBox('Не удалось определить версию Windows.'#13#10'Требуется Windows 10 версии 1903 или новее.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if ver < 10 then
  begin
    MsgBox('Требуется Windows 10 версии 1903 или новее.', mbError, MB_OK);
    Result := False;
  end;
end;
