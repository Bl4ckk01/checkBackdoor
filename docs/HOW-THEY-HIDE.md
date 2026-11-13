# How backdoors hide (and how CheckBackdoor looks for them)

A backdoor has to do three things: **stay** on the PC after a restart, **go unnoticed** and
**communicate** with whoever controls it. Each of these leaves traces: CheckBackdoor looks for
them. The `Txxxx` codes are the techniques of the [MITRE ATT&CK](https://attack.mitre.org)
framework, the reference catalog of the techniques attackers use.

## What usually comes with cracks, keygens and pirated games

| Family | What it does | Typical traces |
|---|---|---|
| **Cryptominers** (XMRig and derivatives) | Uses the CPU/GPU to mine cryptocurrency | Scheduled task, high CPU while idle, Defender exclusions, connections on ports 3333/14444 |
| **Infostealers** (RedLine, Lumma, Vidar...) | Steals passwords, cookies and wallets from the browser, then often deletes itself | Often **no persistent trace**: past Defender detections, files in Temp |
| **RATs** (AsyncRAT, njRAT, Remcos, Quasar, NetSupport) | Full remote control: screen, webcam, keyboard, files | Run key or scheduled task, constant connection to an IP, known ports |
| **Loaders / droppers** | Download other malware later | PowerShell with `-EncodedCommand`, `mshta`, `certutil`, VBS scripts in AppData |
| **Crackonosh** | A miner that disables Defender by rebooting into Safe Mode | Services in `SafeBoot`, Windows Update removed, `safeboot` flag in the BCD |

The first sign is almost always the same: **the crack asks you to disable the antivirus or to
exclude a folder**. From that moment, whatever it contains gets through unchecked.

## Persistence techniques (staying after a restart)

| Technique | Where | Check | Module |
|---|---|---|---|
| Run/RunOnce keys | `HK*\...\CurrentVersion\Run` | Analyzes every entry: signature, path, command | Persistence |
| Startup folder | `shell:startup` | Files and shortcuts, resolves `.lnk` files | Persistence |
| Scheduled tasks (T1053.005) | Task Scheduler | Analyzes all actions, including under `\Microsoft\` | ScheduledTasks |
| Hidden "Tarrask" tasks | `TaskCache\Tree` registry without `SD` | Compares the registry with the visible tasks | ScheduledTasks |
| Services (T1543.003) | `services.msc` | Executable or `ServiceDll` of every service | Services |
| Kernel drivers / rootkits (T1014) | `System32\drivers` | Signature and location of every active driver | Services |
| WMI subscriptions (T1546.003) | `root\subscription` | Consumers that run commands/scripts | Wmi |
| Winlogon Shell/Userinit (T1547.004) | Winlogon registry | Comparison with the factory values | Persistence |
| IFEO Debugger (T1546.012) | `Image File Execution Options` | Program hijacking, sethc/utilman | Persistence |
| AppInit_DLLs (T1546.010) | Registry | DLLs injected into every process | Persistence |
| COM hijacking (T1546.015) | `HKCU\Software\Classes\CLSID` | Per-user CLSIDs that override system ones | Persistence |
| LSA packages (T1547.005) | `Control\Lsa` | Non-standard DLLs loaded by lsass | Persistence |
| Netsh helpers, print monitors, Active Setup, BootExecute, cmd AutoRun, logon scripts | Various keys | Command analysis | Persistence |
| Moved Startup folder | `User Shell Folders\Startup` | Comparison with the default path, analysis of the files in the new folder | AutorunExtra |
| PowerShell profiles (T1546.013) | System and per-user `profile.ps1` | Lines that download, decode or disable AMSI | AutorunExtra |
| BITS jobs (T1197) | `bitsadmin /list` | Jobs with a notify command | AutorunExtra |
| AppCertDlls (T1546.009), compatibility databases (T1546.011) | `Session Manager\AppCertDlls`, `AppCompatFlags\InstalledSDB` | DLLs loaded into other processes, SDBs outside AppPatch | AutorunExtra |
| Office (T1137) | "Office test" key, add-ins, `XLSTART`, `Word\STARTUP` | DLLs and files opened at every Office start | AutorunExtra |
| Winsock providers | `WinSock2\Parameters` | Non-Microsoft DLLs loaded by every program that uses the network | AutorunExtra |
| Tasks only as XML | `System32\Tasks` | Task files that Windows does not list | ScheduledTasks |
| Accessibility backdoors (T1546.008) | `sethc.exe`, `utilman.exe` | Signature and hash compared with cmd.exe | Security |

## Hiding techniques (going unnoticed)

- **Masquerading (T1036)**: names like `svchost.exe` outside System32, or almost identical
  (`svch0st.exe`, `scvhost.exe`). CheckBackdoor checks the path, the distance between names and
  the parent process (the real `svchost.exe` is started only by `services.exe`).
- **User folders**: `AppData`, `Temp`, `ProgramData`, `Users\Public` are writable without
  privileges. Unsigned executables there, especially at the root, are suspicious.
- **Hidden attributes and ADS streams (T1564)**: files with the hidden/system attribute and data
  hidden "inside" another file (Alternate Data Streams).
- **Random names** (`xkqzvbte.exe`, `a8f3c1d9.exe`), typical of droppers.
- **LOLBins (T1218)**: using legitimate Microsoft programs (`mshta`, `rundll32`, `regsvr32`,
  `certutil`, `bitsadmin`, `powershell`) to run code. The file is signed by Microsoft, so
  CheckBackdoor analyzes the **command line** and the file passed as an argument.
- **Obfuscated commands**: PowerShell with `-EncodedCommand`, `-WindowStyle Hidden`, `IEX`,
  `FromBase64String`.
- **Weakening defenses (T1562)**: Defender exclusions, real-time protection off, group
  policies, Windows Update disabled, a `hosts` file that blocks antivirus sites, UAC disabled,
  firewall off.
- **"Clever" miners**: they stop when you open Task Manager. CheckBackdoor measures the CPU
  without opening it.

## The browser: where passwords end up

Many crack malware families do not stay as a program but as a **browser extension** (T1176):
they see every page, read session cookies (which let someone into accounts without a
password) and can replace wallet addresses in pages.

| Technique | How it hides | Check |
|---|---|---|
| Extension loaded from a folder | Developer mode or `--load-extension` in the shortcut: no store review | "Folder" or "command line" origin, shortcuts with parameters |
| Extension forced by a policy | `ExtensionInstallForcelist`: the Remove button is locked and "Managed by your organization" shows up | Chrome, Edge, Brave and Firefox policies in the registry |
| Extension pulled from the store | It was in the store, then removed for malware, but stays installed | The field the browser uses to mark it as malicious |
| Private update server | Updates from an attacker's server and can change code at any time | `update_url` different from the official stores |
| Remote control of the browser | Recent stealers start the browser with `--remote-debugging-port` to read cookies, bypassing encryption | Browser processes and shortcuts with that parameter |
| Search hijacking | A policy forces search engine, home page or proxy | `DefaultSearchProvider*`, `HomepageLocation`, `Proxy*` policies |

## Even before opening it: the tricks in the file

Many of these tricks can be seen **before** running the file (`Check-File.bat`):

| Trick | What it is for | Check |
|---|---|---|
| Double extension (`photo.jpg.exe`) and the character that reverses text (U+202E) | Making a program look like an image or a document | File name |
| Packers and protectors (UPX, Themida, VMProtect) | Hiding the code from antivirus products | Section names and entropy |
| A file inflated with zeros up to hundreds of MB | Exceeding the size limits of antivirus products and VirusTotal: the file is not analyzed | Appended data with entropy close to zero |
| An archive with a `.lnk` shortcut or a script | The user "opens the document" and instead starts PowerShell | Zip contents, shortcut target |
| An unsigned Windows DLL next to the game (`version.dll`, `winmm.dll`, `dinput8.dll`) | The game loads the attacker's DLL instead of the system one (T1574.002) | DLLs with system names and no signature in the folder |
| Replaced game client DLL (`steam_api64.dll`) | It is the heart of the crack and runs at every start: whoever changed it can add more code | DLL signature |

## Inside apps: stealer injections (T1554)

Some stealers leave no program to start: they **change the code of an app you already use**,
which from then on runs it by itself.

- **Discord**: `discord_desktop_core\index.js` normally contains a single line. Stealers add
  code that sends the account token to a webhook at every start. The token is enough to get into
  the account without a password, and the change survives the removal of the malware.
- **Exodus and Atomic Wallet**: `app.asar`, the app code, is replaced to send the recovery
  phrase when you type it.

CheckBackdoor compares `index.js` with the original content (recognizing BetterDiscord) and
flags an `app.asar` changed after installation or containing channels to send data (Discord
webhooks, Telegram bots, file-sharing services).

## The traces that remain: the timeline

Malware can delete its own files after installing itself, but Windows records many things in
its logs. CheckBackdoor reads the last 30 days:

- **Installed services (event 7045)**: a remote access tool that installs itself as a service,
  runs a command and removes itself still leaves this event.
- **Defender (5001, 5007, 1116-1119)**: when it was turned off, which exclusions were added and
  which threats it found, with the outcome.
- **Accounts (4720, 4732)**: accounts created or added to the administrators (reading them
  needs the administrator).
- **PowerShell scripts (4104)**: Windows records scripts with suspicious keywords by itself,
  even without any configuration.
- **BAM key**: the last run of every program, per user. It shows what started from Downloads,
  Desktop or Temp, even if the file is no longer there.

Noisy events are left out: signed drivers that reinstall at every boot (VPN, anti-cheat) and
the modules Windows generates for its own commands.

## Communication and remote access techniques

- **C2 connections (T1071)**: unsigned programs in user folders connected to public IPs,
  default ports of known RATs (4444, 5552, 6606/7707/8808, 2404...), command interpreters with
  open connections.
- **"Bind" backdoors (T1571)**: a program listening on a port waits for the attacker.
- **Remote control tools (T1219)**: AnyDesk, TeamViewer, RustDesk, NetSupport, ScreenConnect...
  legitimate but often installed secretly.
- **Forced Remote Desktop**: RDP Wrapper on Windows Home, changed TermService `ServiceDll`.
- **Hidden accounts (T1136)**: administrators hidden from the sign-in screen.
- **Proxies and root certificates (T1090, T1553.004)**: to intercept HTTPS traffic.

## What CheckBackdoor CANNOT see

- A **kernel rootkit that is already active** can lie to the operating system itself: that
  needs a scan from outside (Microsoft Defender Offline, antivirus boot disk).
- **Memory-only malware** that has not written anything to disk yet.
- **Stealers that are already "gone"**: they steal the data in a few seconds and delete
  themselves. If the crack was a stealer, the only remedy is changing passwords from a clean
  device.
- **Firmware/BIOS backdoors** (very rare for "common" malware).

## Sources

- MITRE ATT&CK – Persistence (TA0003) and Defense Evasion (TA0005): https://attack.mitre.org
- MITRE ATT&CK T1546.012 (IFEO): https://attack.mitre.org/techniques/T1546/012
- Elastic – detecting COM hijacking: https://www.elastic.co/guide/en/security/8.5/component-object-model-hijacking.html
- Gridinsoft – dangers of cracked software: https://blog.gridinsoft.com/5-dangers-cracked-software/
- Gridinsoft – IFEO hijack: https://blog.gridinsoft.com/image-file-execution-options-hijack/
- Hackread – Crackonosh in pirated games: https://www.hackread.com/pirated-games-malware-disable-windows-defender/
- Tria.ge – analysis of an XMRig miner distributed as a crack: https://tria.ge/240626-lhyhma1cmj
- ManageEngine – Masquerading T1036: https://www.manageengine.com/log-management/mitre-attack/defense-evasion/masquerading.html
- LOLBAS Project: https://lolbas-project.github.io
