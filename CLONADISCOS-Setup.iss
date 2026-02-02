; ===============================================================================
; CLONADISCOS - Instalador Inno Setup
; Clonador de discos ultra rapido
; ===============================================================================

#define MyAppName "CLONADISCOS"
#define MyAppVersion "1.0"
#define MyAppPublisher "ARCAMIA-MEMMEM"
#define MyAppURL "https://clonadiscos.com"
#define MyAppExeName "CLONADISCOS.exe"

[Setup]
; Identificador unico de la app
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; Permitir al usuario elegir si crear icono en escritorio
AllowNoIcons=yes
; Carpeta de salida del instalador
OutputDir=.\Output
OutputBaseFilename=CLONADISCOS-Setup
; Icono del instalador
SetupIconFile=.\clonadiscos.ico
; Compresion LZMA2 (mejor ratio)
Compression=lzma2/ultra64
SolidCompression=yes
; Interfaz moderna
WizardStyle=modern
; Requiere admin para instalar
PrivilegesRequired=admin
; Info de version
VersionInfoVersion=1.0.0.0
VersionInfoCompany=ARCAMIA-MEMMEM
VersionInfoDescription=Clonador de discos ultra rapido
VersionInfoCopyright=ARCAMIA-MEMMEM 2026
; Arquitectura
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Desinstalador
UninstallDisplayIcon={app}\clonadiscos.ico
UninstallDisplayName={#MyAppName}

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Archivos principales (SIN EXE para evitar falsos positivos de antivirus)
Source: ".\CLONADISCOS.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\clonadiscos.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\LANZADOR.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Menu Inicio - Apunta a PowerShell directamente
Name: "{group}\{#MyAppName}"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\CLONADISCOS.ps1"""; IconFilename: "{app}\clonadiscos.ico"; WorkingDir: "{app}"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
; Escritorio
Name: "{autodesktop}\{#MyAppName}"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\CLONADISCOS.ps1"""; IconFilename: "{app}\clonadiscos.ico"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Opcion de ejecutar al terminar la instalacion
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\CLONADISCOS.ps1"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
// Verificar que PowerShell esta disponible
function InitializeSetup(): Boolean;
var
  PSPath: String;
begin
  PSPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PSPath) then
  begin
    MsgBox('CLONADISCOS requiere PowerShell para funcionar.' + #13#10 +
           'PowerShell no se encontro en este sistema.', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;
