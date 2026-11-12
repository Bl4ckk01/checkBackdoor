# Eventi della scansione (`checkbackdoor.events/1`)

Con `-EventsFile <percorso>` la scansione scrive il suo avanzamento in un file **JSON Lines**:
una riga per evento, aggiunta in coda appena succede. È il contratto tra il motore in PowerShell
e chi lo segue dal vivo, come l'app con interfaccia.

```powershell
.\CheckBackdoor.ps1 -EventsFile "$env:TEMP\scan-1234.jsonl" -Quiet -NoOpen
```

`-Quiet` toglie ogni output dalla console. Se serve rilanciarsi come amministratore, la nuova
finestra è nascosta e non resta in attesa di INVIO.

## Perché un file e non la console

Quando la scansione chiede i privilegi di amministratore (UAC), Windows avvia un **nuovo
processo** che non può scrivere sulla console di chi l'ha lanciato. Può però scrivere sullo
stesso file: chi legge vede gli eventi del processo amministratore subito dopo `scan.elevating`.

## Forma di ogni riga

```json
{"schema":"checkbackdoor.events/1","seq":3,"time":"2026-11-10T21:04:12.3456789+01:00","pid":1234,"type":"check.started","data":{...}}
```

| Campo | Significato |
|---|---|
| `schema` | Versione del formato. Cambia (`/2`) solo con modifiche incompatibili; campi nuovi in `data` non cambiano la versione. |
| `seq` | Numero progressivo **dentro un processo**: riparte da 1 nel processo amministratore. Per l'ordine globale usa l'ordine delle righe. |
| `time` | Data e ora ISO 8601 con fuso orario. |
| `pid` | Processo che ha scritto l'evento. Dopo `scan.elevating` diventa quello del processo amministratore: è il processo da sorvegliare. |
| `type` | Tipo di evento, vedi sotto. |
| `data` | Contenuto, diverso per tipo. |

Il file viene **aggiunto, mai sovrascritto**: usa un file nuovo per ogni scansione. Si può leggere
mentre la scansione scrive (è aperto con condivisione in lettura). Una riga è completa solo quando
termina con `\n`: se l'ultima riga letta non ha il ritorno a capo, rileggila al giro successivo.

## Tipi di evento

### Prima della scansione

| Tipo | `data` | Quando |
|---|---|---|
| `scan.elevating` | `message` | Sta per chiedere i privilegi di amministratore. Segue `scan.started` dal processo amministratore, oppure un `warning` "Privilegi negati" e `scan.started` dallo stesso processo. |

### Durante la scansione

| Tipo | `data` | Note |
|---|---|---|
| `scan.started` | `version`, `mode` (`Scan` o `File`), `target` (il file controllato con `-File`), `computer`, `user`, `admin`, `deep`, `skipped[]`, `compareTo`, `compareLast`, `virusTotal`, `outputDir`, `checks[]` (`id`, `label`) | Elenca i controlli che verranno eseguiti, nell'ordine. |
| `check.started` | `id`, `label`, `index`, `total` | `index`/`total` valgono per i controlli di `checks[]`. |
| `finding` | `check`, `finding` | Una segnalazione nuova. `finding` ha gli stessi campi del report JSON, incluso `Id`. `Remedy` è presente solo se l'elemento si può disattivare con `Azioni.ps1` (`Kind`: `RegistryValue`, `File`, `ScheduledTask` o `Service`; `Admin`: se serve l'amministratore). |
| `warning` | `check`, `message` | Avviso non bloccante (non amministratore, lista bianca non valida, limite di VirusTotal). |
| `check.completed` | `id`, `status` (`ok` / `error`), `error`, `durationMs`, `findings` | Un errore in un controllo non ferma gli altri. |
| `finding.updated` | `check`, `finding` | Una segnalazione già inviata cambia: oggi solo dopo VirusTotal (gravità e motivi). Sostituiscila usando `Id`. |

Dopo i controlli di `checks[]` possono arrivare due passi extra, con i loro `check.started` e
`check.completed` ma **senza** `index`/`total`:

- `VirusTotal`, se è stata fornita una chiave API;
- `Compare`, il confronto con una scansione precedente, che emette segnalazioni nella categoria
  "Novita' dalla scansione precedente".

### Fine

| Tipo | `data` |
|---|---|
| `scan.completed` | `exitCode` (0 nessun indizio, 1 da verificare, 2 rischio alto), `durationMs`, `ignored` (elementi nascosti dalla lista bianca), `counts` (`Alto`, `Medio`, `Basso`, `Info`), `errors[]`, `report` (`html`, `json`, `csv`: percorsi completi) |
| `scan.failed` | `message`, `check` |
| `scan.cancelled` | `durationMs`, `message` |

Ogni scansione termina con **uno solo** di questi tre.

## Annullare una scansione

Crea un file con lo stesso nome del file di eventi più `.cancel` (ad esempio `scan-1234.jsonl.cancel`).
La scansione lo controlla prima di ogni passo, lo cancella, scrive `scan.cancelled` ed esce con
codice 3, senza produrre il report. Si usa un file e non un segnale al processo perché un'app che
gira come utente normale non può terminare il processo amministratore. Un controllo già iniziato
termina prima di fermarsi: il più lento, sui file, può richiedere un paio di minuti. Se il processo indicato dall'ultimo `pid` termina
senza nessuno dei due, la scansione è stata interrotta (chiusura forzata, crash).

## L'ID delle segnalazioni

`Id` sono 16 cifre esadecimali calcolate da area, titolo, percorso e dettaglio (senza distinguere
maiuscole e minuscole). Lo stesso elemento ha lo stesso `Id` in ogni scansione, anche se la sua
gravità cambia. Serve per aggiornare una segnalazione (`finding.updated`), per confrontare scansioni
e, in seguito, per le azioni sul singolo elemento.

Gli elementi in lista bianca (`allowlist.json`, `allowlist.local.json`) vengono scartati **durante**
la scansione: non generano eventi e sono contati in `ignored`.

## Esempio

```jsonl
{"schema":"checkbackdoor.events/1","seq":1,"time":"...","pid":4120,"type":"scan.started","data":{"version":"1.2.0","admin":true,"checks":[{"id":"Security","label":"Difese di Windows (Defender, esclusioni, UAC, aggiornamenti)"}, ...]}}
{"schema":"checkbackdoor.events/1","seq":2,"time":"...","pid":4120,"type":"check.started","data":{"id":"Security","label":"Difese di Windows ...","index":1,"total":11}}
{"schema":"checkbackdoor.events/1","seq":3,"time":"...","pid":4120,"type":"finding","data":{"check":"Security","finding":{"Id":"4a4c75afd4144cd0","Severity":"Medio","Category":"Difese di Windows","Title":"...","Reasons":["..."]}}}
{"schema":"checkbackdoor.events/1","seq":4,"time":"...","pid":4120,"type":"check.completed","data":{"id":"Security","status":"ok","error":null,"durationMs":2612,"findings":1}}
{"schema":"checkbackdoor.events/1","seq":40,"time":"...","pid":4120,"type":"scan.completed","data":{"exitCode":1,"counts":{"Alto":0,"Medio":6,"Basso":5,"Info":3},"report":{"html":"C:\\...\\scansione_20261110_210455.html", ...}}}
```

## Il report JSON

Anche il file `scansione_*.json` ha una versione: `Meta.Schema` vale `checkbackdoor.report/1`. Ogni
segnalazione contiene `Id` e `Check` (il controllo che l'ha prodotta), come negli eventi.
