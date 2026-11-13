# Roadmap

CheckBackdoor grows in two directions: **better checks** for the traces backdoors and stealers
leave on Windows, and **software with an interface** that replaces the command-line script
without losing transparency or privacy (no data leaves the PC).

## Phases

| Phase | Content | Status |
|---|---|---|
| 0 | License and warning, automated tests (Pester 5), automated checks on GitHub Actions | done (GitHub Actions to verify at the first push) |
| 1 | The engine emits structured events (progress and findings) with a versioned format ([docs/EVENTS.md](docs/EVENTS.md)) | done |
| 2 | Checking a file before opening it; injections into Discord clients and wallets | done |
| 3 | App: Home, Scan in progress, Results (read-only) | done |
| 4 | Timeline from the event logs; startup locations not yet covered | done |
| 5 | App: Comparison, Settings, actions with backup and Undo, scheduled scan | done |
| 6 | Validation on virtual machines, signed installer, first release | ready: VM runs, signing certificate and publishing still to do |

## Checks to add

In order of value for people who download cracks and games from unofficial sources.

1. **Checking a file before opening it** (`-File`):
   - digital signature and hash on VirusTotal;
   - source site (Zone.Identifier);
   - packing or obfuscation (entropy, UPX sections);
   - data appended to the executable;
   - unsigned DLLs with system names in the same folder (DLL side-loading).
2. **Stealer injections:** changed Discord `index.js`, Exodus and Atomic Wallet `app.asar`.
3. **Timeline:**
   - events 7045 (new service);
   - 5001 and 5007 (Defender changed);
   - 1116 and 1117 (detections);
   - 4720 and 4732 (accounts and administrators);
   - 4104 (PowerShell);
   - BAM key (last run of programs).
4. **Startup locations not yet covered:**
   - PowerShell profiles;
   - Startup folder moved through `User Shell Folders`;
   - BITS jobs;
   - AppCertDlls;
   - compatibility databases (SDB);
   - Office add-ins;
   - Winsock providers;
   - scheduled tasks present only as XML.
5. **Measuring effectiveness:**
   - persistence simulated with Atomic Red Team in a virtual machine, with a table of the
     techniques detected;
   - tests on Windows 10 and on Windows in other languages.

## Software with an interface

- **Technology:** .NET 10 (LTS) with WPF and WebView2. It reuses the report interface (see
  `DESIGN.md`), produces a single signable executable and keeps the scan engine in PowerShell.
- **Two processes:** the interface runs as a normal user. Only the scan asks for administrator
  rights and sends progress and findings to the interface.
- **Screens:**
  - Home: latest verdict, start of the scan, area to drop a file to check;
  - Scan in progress: the areas tick off live;
  - Results;
  - Comparison and history;
  - Settings: VirusTotal key encrypted with DPAPI, allowlist, scheduled scan.
- **Actions on each finding:**
  - open the path;
  - look it up on VirusTotal;
  - ignore (allowlist);
  - "Disable": always with a backup and an Undo button, never deletions.

## Principles that do not change

- Read-only by default; every change to the system can be undone.
- No data sent, except hashes to VirusTotal and only if the user turns it on.
- Every finding explains why it is suspicious and what to do.
