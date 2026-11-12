; Installatore di CheckBackdoor (Inno Setup 6). Lo compila tools\Build-Release.ps1:
;   ISCC.exe /DAppVersion=1.2.0 /DSourceDir=<app pubblicata> /DOutputDir=<dist> /DRootDir=<repository>
; Installa in Program Files (servono i privilegi di amministratore): il motore viene
; eseguito come amministratore, quindi i suoi file devono stare dove un programma
; dell'utente non puo' modificarli. Report, backup e impostazioni stanno in
; %LOCALAPPDATA%\CheckBackdoor e restano dopo la disinstallazione (servono per "Annulla").

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
; Chi aveva la versione per utente in %LOCALAPPDATA% non deve restare li': quella cartella
; la puo' modificare qualsiasi programma, e il motore viene poi eseguito come amministratore
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
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
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
; La verifica programmata punta al programma installato: senza di esso non deve restare
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""\CheckBackdoor\Verifica settimanale"" /F"; Flags: runhidden; RunOnceId: "RimuoviVerificaProgrammata"
