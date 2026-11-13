; CheckBackdoor installer (Inno Setup 6). Built by tools\Build-Release.ps1:
;   ISCC.exe /DAppVersion=1.3.0 /DSourceDir=<published app> /DOutputDir=<dist> /DRootDir=<repository>
; Installs to Program Files (administrator rights needed): the engine runs as
; administrator, so its files must live where a user program cannot change them.
; Reports, backups and settings live in %LOCALAPPDATA%\CheckBackdoor and stay after
; uninstalling (Undo needs them).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F3E2B1A-8C4D-4B7E-9A2F-CB0D5E7A1C93}
AppName=CheckBackdoor
AppVersion={#AppVersion}
AppVerName=CheckBackdoor {#AppVersion}
AppPublisher=The CheckBackdoor contributors
DefaultDirName={autopf}\CheckBackdoor
; Whoever had the per-user version in %LOCALAPPDATA% must not stay there: any program can
; change that folder, and the engine then runs as administrator
UsePreviousAppDir=no
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=CheckBackdoor-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayIcon={app}\CheckBackdoor.exe
UninstallDisplayName=CheckBackdoor
LicenseFile={#RootDir}\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\CheckBackdoor"; Filename: "{app}\CheckBackdoor.exe"
Name: "{autodesktop}\CheckBackdoor"; Filename: "{app}\CheckBackdoor.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\CheckBackdoor.exe"; Description: "{cm:LaunchProgram,CheckBackdoor}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; The scheduled scan points to the installed program: it must not stay behind without it
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""\CheckBackdoor\Weekly scan"" /F"; Flags: runhidden; RunOnceId: "RemoveScheduledScan"
