# Scan events (`checkbackdoor.events/1`)

With `-EventsFile <path>` the scan writes its progress to a **JSON Lines** file: one line per
event, appended as soon as it happens. It is the contract between the PowerShell engine and
whoever follows it live, such as the app with an interface.

```powershell
.\CheckBackdoor.ps1 -EventsFile "$env:TEMP\scan-1234.jsonl" -Quiet -NoOpen
```

`-Quiet` removes all console output. If the scan needs to restart as administrator, the new
window is hidden and does not wait for ENTER.

## Why a file and not the console

When the scan asks for administrator rights (UAC), Windows starts a **new process** that
cannot write to the console of whoever started it. It can, however, write to the same file:
the reader sees the events of the administrator process right after `scan.elevating`.

## Shape of each line

```json
{"schema":"checkbackdoor.events/1","seq":3,"time":"2026-11-10T21:04:12.3456789+01:00","pid":1234,"type":"check.started","data":{...}}
```

| Field | Meaning |
|---|---|
| `schema` | Format version. It changes (`/2`) only with incompatible changes; new fields in `data` do not change the version. |
| `seq` | Sequence number **within one process**: it restarts from 1 in the administrator process. For the global order use the order of the lines. |
| `time` | ISO 8601 date and time with time zone. |
| `pid` | The process that wrote the event. After `scan.elevating` it becomes the administrator process: that is the process to watch. |
| `type` | Event type, see below. |
| `data` | Content, different for each type. |

The file is **appended to, never overwritten**: use a new file for each scan. It can be read
while the scan writes (it is opened with read sharing). A line is complete only when it ends
with `\n`: if the last line read has no line break, read it again on the next pass.

## Event types

### Before the scan

| Type | `data` | When |
|---|---|---|
| `scan.elevating` | `message` | It is about to ask for administrator rights. Followed by `scan.started` from the administrator process, or by a "rights denied" `warning` and `scan.started` from the same process. |

### During the scan

| Type | `data` | Notes |
|---|---|---|
| `scan.started` | `version`, `mode` (`Scan` or `File`), `target` (the file checked with `-File`), `computer`, `user`, `admin`, `deep`, `skipped[]`, `compareTo`, `compareLast`, `virusTotal`, `outputDir`, `checks[]` (`id`, `label`) | Lists the checks that will run, in order. |
| `check.started` | `id`, `label`, `index`, `total` | `index`/`total` apply to the checks in `checks[]`. |
| `finding` | `check`, `finding` | A new finding. `finding` has the same fields as the JSON report, `Id` included. `Remedy` is present only if the item can be disabled with `Actions.ps1` (`Kind`: `RegistryValue`, `File`, `ScheduledTask` or `Service`; `Admin`: whether the administrator is needed). |
| `warning` | `check`, `message` | Non-blocking warning (not administrator, invalid allowlist, VirusTotal limit). |
| `check.completed` | `id`, `status` (`ok` / `error`), `error`, `durationMs`, `findings` | An error in one check does not stop the others. |
| `finding.updated` | `check`, `finding` | A finding already sent changes: today only after VirusTotal (severity and reasons). Replace it using `Id`. |

After the checks in `checks[]` two extra steps may arrive, with their own `check.started` and
`check.completed` but **without** `index`/`total`:

- `VirusTotal`, if an API key was provided;
- `Compare`, the comparison with a previous scan, which emits findings in the category
  "Changes since the previous scan".

### End

| Type | `data` |
|---|---|
| `scan.completed` | `exitCode` (0 no clues, 1 to review, 2 high risk), `durationMs`, `ignored` (items hidden by the allowlist), `counts` (`High`, `Medium`, `Low`, `Info`), `errors[]`, `report` (`html`, `json`, `csv`: full paths) |
| `scan.failed` | `message`, `check` |
| `scan.cancelled` | `durationMs`, `message` |

Every scan ends with **exactly one** of these three.

## Cancelling a scan

Create a file with the same name as the event file plus `.cancel` (for example
`scan-1234.jsonl.cancel`). The scan checks for it before every step, deletes it, writes
`scan.cancelled` and exits with code 3, without producing the report. A file is used instead of
a signal to the process because an app running as a normal user cannot terminate the
administrator process. A check that already started finishes before stopping: the slowest
one, on files, can take a couple of minutes. If the process given by the latest `pid` ends
without any of these events, the scan was interrupted (forced close, crash).

## Finding IDs

`Id` is 16 hexadecimal digits computed from area, title, path and detail (case-insensitive).
The same item has the same `Id` in every scan, even if its severity changes. It is used to
update a finding (`finding.updated`), to compare scans and for the actions on a single item.

Allowlisted items (`allowlist.json`, `allowlist.local.json`) are dropped **during** the scan:
they generate no events and are counted in `ignored`.

## Example

```jsonl
{"schema":"checkbackdoor.events/1","seq":1,"time":"...","pid":4120,"type":"scan.started","data":{"version":"1.3.0","admin":true,"checks":[{"id":"Security","label":"Windows defenses (Defender, exclusions, UAC, updates)"}, ...]}}
{"schema":"checkbackdoor.events/1","seq":2,"time":"...","pid":4120,"type":"check.started","data":{"id":"Security","label":"Windows defenses ...","index":1,"total":11}}
{"schema":"checkbackdoor.events/1","seq":3,"time":"...","pid":4120,"type":"finding","data":{"check":"Security","finding":{"Id":"4a4c75afd4144cd0","Severity":"Medium","Category":"Windows defenses","Title":"...","Reasons":["..."]}}}
{"schema":"checkbackdoor.events/1","seq":4,"time":"...","pid":4120,"type":"check.completed","data":{"id":"Security","status":"ok","error":null,"durationMs":2612,"findings":1}}
{"schema":"checkbackdoor.events/1","seq":40,"time":"...","pid":4120,"type":"scan.completed","data":{"exitCode":1,"counts":{"High":0,"Medium":6,"Low":5,"Info":3},"report":{"html":"C:\\...\\scan_20261110_210455.html", ...}}}
```

## The JSON report

The `scan_*.json` file has a version too: `Meta.Schema` is `checkbackdoor.report/1`. Every
finding contains `Id` and `Check` (the check that produced it), as in the events.
