# Measuring detections in a virtual machine

`tools\Test-Detections.ps1` answers the question "does CheckBackdoor really find these
techniques?" on a real Windows, without using malware.

## What it does

1. Checks that it is running in a virtual machine (otherwise it stops without touching anything).
2. Creates **harmless** persistence techniques, all with the `CBTest` marker:

   | Technique | MITRE | Needs administrator |
   |---|---|---|
   | Run entry (HKCU) with hidden PowerShell and a Base64 command | T1547.001 | no |
   | Script in the Startup folder | T1547.001 | no |
   | Scheduled task with hidden PowerShell | T1053.005 | no |
   | PowerShell profile that downloads and runs | T1546.013 | no |
   | BITS job with a notify command | T1197 | no |
   | IFEO debugger on a program | T1546.012 | yes |
   | Service that starts hidden PowerShell | T1543.003 | yes |
   | Permanent WMI subscription | T1546.003 | yes |
   | Microsoft Defender exclusion | T1562.001 | yes |

   The "payload" is a `Write-Output`. No entry is ever run: the task starts in 2099, the
   service is manual, the WMI filter fires only in 2099, the BITS job points to an `.invalid`
   address.
3. Runs CheckBackdoor and looks for each technique among the findings.
4. **Always removes everything**, even if the scan fails (the PowerShell profile goes back
   to exactly what it was).
5. Writes a table to `report\validation\validation_<date>.md`.

## How to use it

1. Create a virtual machine with Windows 10 or 11 (Hyper-V, VirtualBox, VMware) and take a
   snapshot.
2. Copy the CheckBackdoor folder into the VM.
3. Open PowerShell **as administrator** and run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\Test-Detections.ps1
   ```

4. Repeat in a VM with Windows in another language: some parts read Windows texts.
5. Go back to the snapshot.

The exit code is `0` if all the tested techniques were detected, `1` if some were not, `2` if
the PC does not look like a virtual machine. If your VM is not recognized, add `-SkipVmCheck`.

## Results

To be filled in with the test tables. For each system: Windows version, language,
administrator yes/no, and the table produced by the script.

| System | Language | Techniques detected | Notes |
|---|---|---|---|
| Windows 11 | English | to test | |
| Windows 11 | another language | to test | |
| Windows 10 | English | to test | |
