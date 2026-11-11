# CheckBackdoor

*[Leggi in italiano](README.md)*

A Windows scanner that looks for **backdoors, RATs, cryptominers and other signs of
compromise**, built for people who downloaded executables, cracks or games from unofficial
sources.

- **Read-only scan**: the scan never changes, deletes or quarantines anything. The app can
  disable an item only when you ask, always with a backup and an Undo button.
- **Nothing to install for the script**: it uses PowerShell 5.1, built into Windows 10/11.
- **No data leaves your PC** (except file hashes, and only if you enable VirusTotal).
- Readable **HTML** report, plus **JSON** and **CSV**. The report works offline: opening it
  makes no network requests.

> **Language.** The interface, the report and the explanations are in **Italian** for now.
> The code, the JSON report and the event format use stable field names, so translations can
> be added later.

> **Disclaimer.** CheckBackdoor is a second opinion, not an antivirus. It looks for the traces
> a backdoor leaves to start again after a reboot and to communicate, but a rootkit that is
> already running can hide even from Windows. "No signs found" **does not guarantee** the PC
> is clean: if you have real doubts, also run Microsoft Defender Offline and, on PCs with
> important data, consider reinstalling Windows. The software is provided "as is", without
> warranty (see [LICENSE](LICENSE)). Download it only from this repository: read
> [SECURITY.md](SECURITY.md).

## Download

From the **Releases** page:

| File | What it is |
|---|---|
| `CheckBackdoor-<version>-setup.exe` | Installer for the current user (no administrator needed). |
| `CheckBackdoor-<version>-win-x64.zip` | Portable app: unzip and run `CheckBackdoor.exe`. |
| `CheckBackdoor-<version>-script.zip` | Just the PowerShell engine, for those who prefer the script. |
| `SHA256SUMS.txt` | Hashes to verify the downloads (`Get-FileHash file -Algorithm SHA256`). |

If the files are not signed, Windows SmartScreen shows a warning: choose *More info*, then
*Run anyway*, only after checking the hash.

## Quick start

**App.** Open CheckBackdoor and press *Avvia la verifica* (start the check). Windows asks for
administrator rights: without them some important checks (Defender exclusions, WMI, system
processes) are incomplete. To check a single file **before opening it**, drag it onto the
window.

**Script.** Double-click **`Avvia-Scansione.bat`**, or from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\CheckBackdoor.ps1
```

To check one file or folder before opening it, drag it onto **`Controlla-File.bat`**, or:

```powershell
.\CheckBackdoor.ps1 -File "$env:USERPROFILE\Downloads\setup.exe"
```

The file is only read, never run. It looks at the digital signature, where it was downloaded
from, packers and obfuscation, data appended to the executable, executables inflated with
zeros to dodge antivirus size limits, double extensions and replaced DLLs next to a game.

## Options

| Parameter | What it does |
|---|---|
| `-File path` | Checks only that file or folder, before you open it. |
| `-Deep` | Deeper scan of user folders, DLLs included. Slower. |
| `-CompareLast` | Compares with the last scan and shows **what changed**. |
| `-CompareTo file.json` | Compares with a specific scan. |
| `-VirusTotalApiKey KEY` | Looks up the hashes of suspicious files on VirusTotal (or `VT_API_KEY`). |
| `-VirusTotalKeyFile file` | Same, with the key encrypted by DPAPI for the current user (the app writes it). |
| `-AllowlistFile file` | An extra allowlist (the app keeps the items you chose to ignore here). |
| `-VirusTotalMax 20` | Maximum number of hashes to look up (free API: 4 per minute). |
| `-Skip Network,FileSystem` | Skips some checks. |
| `-NoOpen` / `-NoElevate` / `-Quiet` | No browser at the end / no administrator request / no console output. |
| `-EventsFile file.jsonl` | Writes progress and findings as they happen ([format](docs/EVENTI.md)). |

Exit codes: `2` high-risk items found, `1` items to review, `0` nothing, `3` scan cancelled,
`4` CheckBackdoor files missing (usually quarantined by the antivirus).

The best trick is **before and after**: run a scan, install or start the suspicious program,
reboot, then run `.\CheckBackdoor.ps1 -CompareLast`. The app does the same from *Storico*
(history) with *Confronta con la precedente*.

## What it checks

| Area | Checks |
|---|---|
| **Windows defenses** | Defender turned off, **exclusions** (the number one sign of cracks), policies that disable it, threat history, Windows Update or firewall disabled |
| **Autostart** | Run/RunOnce keys of every user, Startup folders, Winlogon, IFEO, SilentProcessExit, AppInit_DLLs, LSA, BootExecute, Netsh, print monitors, Active Setup, cmd AutoRun, logon scripts, screensaver, COM hijacking, moved Startup folder, PowerShell profiles, BITS jobs with a command, AppCertDlls, shim databases (SDB), Office add-ins and the "Office test" key, Winsock providers |
| **Scheduled tasks** | Every action, hidden tasks (Tarrask technique), tasks hiding under `\Microsoft\`, tasks that exist only as XML files |
| **Services and drivers** | Executable or DLL of every service, unsigned drivers (rootkits), Safe Mode services (Crackonosh), RDP Wrapper |
| **WMI** | Permanent subscriptions that run commands ("fileless" persistence) |
| **Processes** | Processes disguised as system ones, look-alike names (svch0st), odd parents, suspicious command lines, **miner-like CPU usage** |
| **Network** | Listening ports, connections to public IPs, known RAT ports, hosts file, proxy, firewall, remote-control software, SSH server |
| **Browsers** | Chrome, Edge, Brave, Opera, Vivaldi and Firefox extensions flagged as malware by the browser, loaded from a folder or the command line, forced by a policy, not from the store. It never reads history, cookies or passwords |
| **App injections** | Code added to Discord (the `index.js` stealers modify to grab the token) and to Exodus / Atomic Wallet (`app.asar`) |
| **Accounts** | Unknown or hidden administrators, Administrator/Guest enabled, Remote Desktop, WinRM |
| **Certificates** | Added root certificates (HTTPS interception) |
| **Suspicious files** | Unsigned executables, VBS/JS/HTA scripts, hidden files, random names and ADS streams in AppData, Temp, ProgramData, Public, Recycle Bin |
| **Timeline** | The last 30 days from Windows logs: services installed and then removed (7045), Defender turned off or given new exclusions (5001, 5007), threats found and not removed (1116-1119), accounts created or made administrators (4720, 4732), suspicious PowerShell scripts (4104), programs started from Downloads, Desktop or Temp (BAM key) |

Every item gets a **score** from combined clues (missing or tampered signature, user-writable
folder, hidden window, Base64 command, download from the internet, random name...). Every
finding explains **why** it is suspicious, **what to do**, and links the MITRE ATT&CK
technique and VirusTotal. [docs/COME-SI-NASCONDONO.md](docs/COME-SI-NASCONDONO.md) describes
the techniques (in Italian).

## The app

- Home with the last verdict; the check in progress, with areas ticked off live and a Cancel
  button; the results in the same design as the report.
- An action on every finding: **show the file**, **ignore it in future checks**, **disable**
  (autostart entries, Startup folder files, scheduled tasks, services). Disabling never deletes
  anything: a backup is saved first and **Undo** restores it. Windows tasks and Microsoft
  services are refused.
- **History** and **comparison** between two checks: new and resolved findings, items added,
  changed (usually updates) and removed.
- **Settings**: VirusTotal key (encrypted with DPAPI for your Windows user, never passed on the
  command line), a weekly **scheduled check**, the changes made with their Undo, ignored items.

The app runs as a normal user: only the check and the actions that touch system parts (HKLM,
tasks, services) ask for administrator rights. The interface loads nothing from the internet.
Reports, backups and settings stay in `%LOCALAPPDATA%\CheckBackdoor`, and stay there after
uninstalling (they are needed for Undo).

## If your antivirus blocks CheckBackdoor

To find malware, CheckBackdoor reads the same places malware reads: autostart keys, browser
extensions, Discord and wallet files. Its files also contain the words it looks for (obfuscated
commands, miner parameters...). Some antivirus products, especially those with behaviour
analysis such as Kaspersky, may mistake it for a threat and quarantine `CheckBackdoor.ps1` or a
module. The launchers, the script and the app tell you when a file is missing.

1. **Restore the file from quarantine**, or download the project again (`git checkout -- .`).
2. **Add the folder to the antivirus exclusions.**
3. **Report the false positive** to the antivirus vendor, so it improves for everyone.

Before excluding the folder, make sure you downloaded CheckBackdoor from its repository: all
the code is readable, which is why it is written in PowerShell.

## Limits

It cannot see a rootkit already running in the kernel (use Microsoft Defender Offline), malware
that lives only in memory, or a stealer that already sent your passwords and left. Many
"to review" items are legitimate software: hide the ones you checked by adding them to
`allowlist.local.json` or with *Ignora* in the app.

## Development and tests

```powershell
Install-Module Pester -Scope CurrentUser -SkipPublisherCheck   # once
.\tests\Invoke-Tests.ps1                                       # all tests
dotnet build app\CheckBackdoor.App -c Release                  # the app (.NET 10 SDK)
.\tools\Build-Release.ps1                                      # release packages in dist\
```

- **Tests**: Pester 5 for the engine (unit, report, end-to-end scans, privacy checks: no network
  calls outside VirusTotal, no personal data in published files), plus a headless app smoke
  test (`CheckBackdoor.exe --smoke <dir>`). GitHub Actions runs them on every push.
- **Detection check in a virtual machine**: `tools\Prova-Rilevamenti.ps1` creates *harmless*
  persistence (Run key, task, service, WMI, Defender exclusion... whose payload is a
  `Write-Output`), runs the scan, reports which ones were found, and removes everything. It
  refuses to run outside a VM. See [docs/VALIDAZIONE.md](docs/VALIDAZIONE.md).
- **Releases**: pushing a `v1.2.0` tag builds a **draft** release on GitHub with the installer,
  the zips and the hashes. With the `SIGNING_PFX_BASE64` and `SIGNING_PFX_PASSWORD` secrets
  (a code-signing certificate from a recognised authority) the exe, the scripts and the
  installer are signed.

## License

MIT. See [LICENSE](LICENSE).
