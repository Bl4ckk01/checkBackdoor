# Security

## Downloading CheckBackdoor safely

A tool that runs as administrator is an ideal target for modified copies.

- Download it only from this GitHub repository, never from sites, videos or messages that
  repost it.
- Before running it, compare the SHA-256 hash of the archive with the one published on the
  release page:
  ```powershell
  Get-FileHash .\CheckBackdoor.zip -Algorithm SHA256
  ```
- The code is readable PowerShell: you can open `CheckBackdoor.ps1` and the `modules\` folder
  and check that it downloads and sends nothing. The only possible connection is to VirusTotal,
  and only if you provide an API key yourself (`-VirusTotalApiKey`).

## Where to keep it

When it asks for administrator rights, CheckBackdoor runs its own files with those rights. If
they are in a folder any program can change (Downloads, Desktop, AppData), malware already on
the PC can rewrite them and get those rights at the next scan.

- The installer puts the program in `Program Files`, which only administrators can change:
  this is the recommended way.
- If you use the zip or the scripts, extract them to a folder protected the same way, or run
  the scan without elevation (`-NoElevate`): it will be less complete, but no changeable file
  will run as administrator.
- Releases have a provenance attestation. To verify a downloaded file:
  ```powershell
  gh attestation verify .\CheckBackdoor-<version>-setup.exe --repo <owner>/<repository>
  ```

## What does not trust what

- **Allowlist.** `allowlist.local.json` and the items ignored from the app are user files:
  malware can write to them. Rules that are too broad are not applied and show up among the
  findings, and the report always lists what was hidden.
- **"Disable" and "Undo".** They act only on startup keys, Startup folders, non-Windows tasks
  and services that belong neither to Microsoft nor to the antivirus. As administrator,
  backups are written and read only in `%ProgramData%\CheckBackdoor\backup`.
- **Report.** The file names and commands it contains are chosen by whoever wrote the malware:
  they are always shown as text, and a Content-Security-Policy blocks any other script.

## Reporting a vulnerability

If you find a security problem in the scanner, report it privately with the "Report a
vulnerability" feature of the GitHub **Security** tab, not with a public issue. For example: a
report that runs code when opened, a path that lets someone read or change files they should
not, or a way to hide persistence from the checks.

## False negatives and false positives

A malicious item that was not detected or a legitimate program that was flagged are not
vulnerabilities: open a normal issue, without attaching the full report. The report contains
data about your PC (user names, paths, installed programs): copy only the finding concerned.
