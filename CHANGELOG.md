# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Engine and app
versions are the same.

## Unreleased

### Fixed
- The timeline reported CheckBackdoor's own modules as suspicious PowerShell scripts: Windows
  logs them (event 4104) and the text read from the log has different line endings from the
  files, so the engine no longer recognized them as its own.

## 1.3.0

The first public release.

### Changed
- **Everything is in English**: interface, report, messages, code, comments and docs. File
  names changed accordingly: `Start-Scan.bat`, `Check-File.bat`, `Actions.ps1`,
  `tools\Test-Detections.ps1`, reports `scan_*` and `check_*`, app data `ignored.json` and
  `settings.json`, scheduled task `\CheckBackdoor\Weekly scan`. Severities are `High`,
  `Medium`, `Low` and `Info`. Reports from earlier versions are not shown in the app history.
- Command-line analysis moved from `Common.ps1` to its own module, `CommandRisk.ps1`.

### Fixed
- The report subtitle glued the date and the Windows version together without a separator.

### Security
- **Install to Program Files** (administrator needed): the engine runs as administrator, so it
  must not live in a folder a user program can change. PowerShell is started by its full path.
- **Protected backups**: changes made as administrator save their backup in
  `%ProgramData%\CheckBackdoor\backup`, writable only by administrators, and "Undo" with those
  rights restores only backups from that folder. A moved file goes back only if its SHA-256
  hash is the one saved.
- **"Disable"** shows the item that will really be changed, does not touch the services of the
  installed antivirus and rejects a request changed after the confirmation (`-RequestSha256`).
- **Allowlist**: rules that are too broad (`*`, `*.exe`, whole user or system folders) are not
  applied and are flagged; an item ignored from the app shows up again if the file changes; the
  report lists everything the allowlist hid, with the rule.
- **Content-Security-Policy** in the report and the interface: only CheckBackdoor scripts run.
- **Release**: GitHub actions pinned to a commit and provenance attestation of the files.

## 1.2.0

### Added
- **Timeline** of the last 30 days from the Windows logs: services installed and then removed,
  Defender turned off or given new exclusions, threats found, accounts created or made
  administrators, suspicious PowerShell scripts, programs started from Downloads and Temp.
- **Lesser-known startup locations**: moved Startup folder, PowerShell profiles, BITS jobs with
  a command, AppCertDlls, compatibility databases, Office add-ins and the "Office test" key,
  Winsock providers, tasks present only as XML files.
- **App**: history and comparison between scans (new, gone, added, changed, removed); settings
  with an encrypted VirusTotal key (DPAPI), weekly scheduled scan, ignored items; actions on
  each finding: show the file, ignore, **disable** with a backup and **Undo**.
- Clear messages when the antivirus quarantines a CheckBackdoor file (exit code 4) and a README
  section on how to restore it.
- Installer, portable app, script package, SHA-256 hashes and optional signing
  (`tools\Build-Release.ps1`); draft release from GitHub Actions.
- A tool to measure detections in a virtual machine.

### Changed
- Signed services that reinstall at every boot (VPN, anti-cheat) no longer fill the timeline.
- Compatibility databases installed in AppPatch are "low risk" (IIS Express installs two).

## 1.1.0

### Added
- Redesigned HTML report, offline, with light and dark themes.
- Checks of browser extensions and of injections into Discord and wallets.
- Checking a file before opening it (`-File`).
- Structured scan events (`-EventsFile`, [docs/EVENTS.md](docs/EVENTS.md)) and cancelling.
- First version of the app with an interface (WPF + WebView2).
- Pester tests, privacy checks and GitHub Actions.
