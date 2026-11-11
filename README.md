# CheckBackdoor

*[Read in English](README.en.md)*

Scanner per Windows che cerca **backdoor, RAT, cryptominer e altri segni di compromissione**,
pensato per chi ha scaricato eseguibili, crack o giochi da fonti non ufficiali.

- **Verifica in sola lettura**: la scansione non modifica, non cancella e non mette in
  quarantena nulla. L'app disattiva un elemento solo se lo chiedi, sempre con un backup e il
  pulsante Annulla.
- **Lo script non richiede installazione**: usa PowerShell 5.1, già presente in ogni Windows 10/11.
- **Nessun dato inviato** a internet (tranne gli hash, e solo se attivi VirusTotal).
- Report **HTML** leggibile, più **JSON** e **CSV**. Il report funziona offline: aprirlo
  non fa nessuna richiesta a internet.

> **Avviso.** CheckBackdoor è un secondo parere, non un antivirus. Cerca le tracce che una
> backdoor lascia per avviarsi e comunicare, ma un rootkit già attivo può nascondersi a Windows
> stesso. "Nessun indizio" **non garantisce** che il PC sia pulito: se hai dubbi fondati, usa
> anche Microsoft Defender Offline e, sui PC con dati importanti, valuta la reinstallazione di
> Windows. Il software è fornito "così com'è", senza garanzie (vedi [LICENSE](LICENSE)).
> Scaricalo solo da questa repository: leggi [SECURITY.md](SECURITY.md).

## Download

Dalla pagina **Releases**:

| File | Cos'è |
|---|---|
| `CheckBackdoor-<versione>-setup.exe` | Installatore per l'utente corrente (non serve l'amministratore). |
| `CheckBackdoor-<versione>-win-x64.zip` | App portatile: estrai e avvia `CheckBackdoor.exe`. |
| `CheckBackdoor-<versione>-script.zip` | Solo il motore PowerShell, per chi preferisce lo script. |
| `SHA256SUMS.txt` | Impronte per verificare i file scaricati (`Get-FileHash file -Algorithm SHA256`). |

Se i file non sono firmati, Windows SmartScreen mostra un avviso: scegli *Ulteriori
informazioni* e poi *Esegui comunque*, solo dopo aver controllato l'impronta.

## Avvio rapido

1. Doppio clic su **`Avvia-Scansione.bat`**.
2. Accetta la richiesta di privilegi di amministratore (senza, alcuni controlli importanti
   come le esclusioni di Defender e WMI sono incompleti).
3. Alla fine si apre il report nel browser. I file restano nella cartella `report\`.

Da PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\CheckBackdoor.ps1
```

### App con interfaccia (anteprima)

In `app\` c'è la prima versione dell'app per Windows. Offre:

- la Home con l'ultimo verdetto;
- la verifica in corso, con le aree che si spuntano dal vivo e il pulsante Annulla;
- il controllo di un file trascinandolo nella finestra;
- i risultati nella stessa grafica del report, con un'azione su ogni segnalazione:
  - **Mostra il file** in Esplora file;
  - **Ignora nelle prossime verifiche** (si ripristina dalle impostazioni);
  - **Disattiva**, per voci di avvio, file nella cartella Esecuzione automatica, attività
    pianificate e servizi. Non cancella mai nulla: prima salva un backup, e **Annulla** riporta
    tutto com'era;
- lo **Storico** delle verifiche e il **Confronto** tra due verifiche: segnalazioni nuove e
  sparite, elementi comparsi, modificati (di solito aggiornamenti) e rimossi;
- le **Impostazioni**: chiave di VirusTotal (cifrata con DPAPI per il tuo utente Windows, non
  passa mai dalla riga di comando), **verifica programmata** settimanale, modifiche fatte con
  il loro Annulla, elementi ignorati.

L'app gira come utente normale: solo la verifica e le azioni che toccano parti di sistema
(HKLM, attività, servizi) chiedono i privilegi di amministratore. L'interfaccia non carica
nulla da internet. Report, backup e impostazioni restano in `%LOCALAPPDATA%\CheckBackdoor`.

La verifica programmata è un'attività di Utilità di pianificazione dell'utente
(`\CheckBackdoor\Verifica settimanale`) e gira senza privilegi di amministratore. CheckBackdoor
la riconosce come propria solo se lancia esattamente il suo `CheckBackdoor.ps1` (stesso
contenuto): un'attività con lo stesso nome che esegue altro viene segnalata come le altre.

Per compilarla serve .NET 10 SDK (`winget install Microsoft.DotNet.SDK.10`):

```powershell
dotnet build app\CheckBackdoor.App -c Release
.\app\CheckBackdoor.App\bin\Release\net10.0-windows\CheckBackdoor.exe
```

Non c'è ancora un installatore: arriverà con la prima release ([ROADMAP.md](ROADMAP.md)).

### Controllare un file prima di aprirlo

Trascina un file (o una cartella) sopra **`Controlla-File.bat`**. Oppure:

```powershell
.\CheckBackdoor.ps1 -File "$env:USERPROFILE\Downloads\setup.exe"
```

Il file viene solo letto, mai eseguito, e non servono i privilegi di amministratore. Il controllo
riguarda:

- la **firma digitale**: assente, valida o manomessa;
- il **sito da cui è stato scaricato**;
- i **nomi ingannevoli**: `foto.jpg.exe`, il carattere invisibile che inverte il testo, spazi
  prima dell'estensione;
- i **compressori** usati per nascondere il codice (UPX, Themida, VMProtect...);
- gli eseguibili **gonfiati di zeri** per superare i limiti di antivirus e VirusTotal (trucco
  tipico degli stealer);
- gli **archivi zip** che contengono collegamenti o doppie estensioni;
- nelle cartelle dei giochi, le **DLL sostituite**: copie non firmate di DLL di Windows, che il
  programma caricherebbe al posto delle originali, e DLL del client di gioco modificate da un
  crack.

Con `-VirusTotalApiKey` verifica l'hash anche quando non trova indizi. I risultati si chiamano
`controllo_*` e non interferiscono con il confronto tra scansioni. La lista bianca qui non si
applica: se chiedi di controllare un file, vedi sempre il risultato.

## Opzioni

| Parametro | Cosa fa |
|---|---|
| `-File percorso` | Controlla solo quel file o quella cartella, prima di aprirlo (vedi sopra). |
| `-Deep` | Scansione più profonda delle cartelle utente, incluse le DLL. Più lenta. |
| `-CompareLast` | Confronta con l'ultima scansione e mostra **cosa è cambiato**. |
| `-CompareTo file.json` | Confronta con una scansione specifica. |
| `-VirusTotalApiKey CHIAVE` | Verifica gli hash dei file sospetti su VirusTotal (o variabile `VT_API_KEY`). |
| `-VirusTotalKeyFile file` | Come sopra, con la chiave cifrata con DPAPI per l'utente corrente (la scrive l'app). |
| `-AllowlistFile file` | Lista bianca in più (l'app ci tiene gli elementi che hai scelto di ignorare). |
| `-VirusTotalMax 20` | Numero massimo di hash da verificare (API gratuita: 4 al minuto). |
| `-Skip Network,FileSystem` | Salta alcuni controlli. |
| `-NoOpen` | Non apre il report alla fine. |
| `-NoElevate` | Non chiede i privilegi di amministratore. |
| `-EventsFile file.jsonl` | Scrive avanzamento e segnalazioni mentre arrivano, per un'interfaccia che segue la scansione ([formato](docs/EVENTI.md)). |
| `-Quiet` | Nessun output in console; con `-EventsFile`, anche la finestra amministratore resta nascosta. |

Codice di uscita: `2` = trovati elementi ad alto rischio, `1` = elementi da verificare, `0` = nulla,
`3` = verifica annullata, `4` = mancano dei file di CheckBackdoor (di solito messi in quarantena dall'antivirus).

### Il trucco più utile: prima e dopo

Prima di provare un programma di cui non ti fidi:

```powershell
.\CheckBackdoor.ps1                 # scansione di riferimento
# ...installi/avvii il programma, riavvii il PC...
.\CheckBackdoor.ps1 -CompareLast    # mostra tutte le voci di avvio, servizi, esclusioni... nuove
```

Così vedi esattamente cosa ha aggiunto al sistema.

## Cosa controlla

| Modulo | Controlli |
|---|---|
| **Difese di Windows** | Defender spento, **esclusioni** (il segnale n°1 dei crack), criteri che lo disattivano, cronologia delle minacce rilevate, Windows Update/firewall disabilitati o rimossi, UAC, programmi di accessibilità sostituiti (sethc/utilman), avvio forzato in Modalità provvisoria |
| **Avvio automatico** | Chiavi Run/RunOnce di tutti gli utenti, cartelle Esecuzione automatica, Winlogon, IFEO, SilentProcessExit, AppInit_DLLs, LSA, BootExecute, Netsh, Print monitor, Active Setup, AutoRun di cmd, script di logon, screensaver, dirottamento COM, cartella Esecuzione automatica spostata, profili PowerShell, processi BITS con comando, AppCertDlls, database di compatibilità (SDB), componenti aggiuntivi e chiave "Office test", provider Winsock |
| **Attività pianificate** | Tutte le azioni, attività nascoste (tecnica Tarrask), attività che si mimetizzano in `\Microsoft\`, attività presenti solo come file XML |
| **Servizi e driver** | Eseguibile o DLL di ogni servizio, driver non firmati (rootkit), servizi in Modalità provvisoria (Crackonosh), RDP Wrapper |
| **WMI** | Sottoscrizioni permanenti che eseguono comandi (persistenza "senza file") |
| **Processi** | Processi travestiti da processi di sistema, nomi simili (svch0st), genitori anomali, righe di comando sospette, **uso CPU anomalo (miner)** |
| **Rete** | Porte in ascolto, connessioni verso IP pubblici, porte di RAT noti, file hosts, proxy, firewall, software di controllo remoto (AnyDesk, NetSupport...), server SSH |
| **Browser** | Estensioni di Chrome, Edge, Brave, Opera, Vivaldi e Firefox: quelle segnalate dal browser come malware, caricate da una cartella o dalla riga di comando, imposte da un criterio, non provenienti da uno store o aggiornate da un server privato. Criteri che dirottano ricerca, pagina iniziale o proxy, o bloccano gli strumenti per sviluppatori. Collegamenti e processi del browser avviati con `--load-extension` o `--remote-debugging-port` (usati dagli stealer per rubare i cookie). Legge solo i dati delle estensioni, mai cronologia, cookie o password |
| **Iniezioni nelle app** | Codice aggiunto a Discord, Discord Canary/PTB e Lightcord (il file `index.js` che gli stealer modificano per rubare il token a ogni avvio; BetterDiscord riconosciuto) e ai wallet Exodus e Atomic (codice modificato dopo l'installazione o con canali di invio dei dati) |
| **Account** | Amministratori sconosciuti, account nascosti, Administrator/Guest attivi, Desktop remoto, WinRM |
| **Certificati** | Certificati radice aggiunti (intercettazione HTTPS) |
| **File sospetti** | Eseguibili non firmati, script VBS/JS/HTA, file nascosti, nomi casuali e flussi ADS in AppData, Temp, ProgramData, Pubblica, Cestino |
| **Linea temporale** | Ultimi 30 giorni dai registri di Windows: servizi installati e poi rimossi (7045), Defender spento o con esclusioni aggiunte (5001, 5007), minacce trovate e non rimosse (1116-1119), account creati o resi amministratori (4720, 4732), script PowerShell sospetti (4104) e programmi avviati da Download, Desktop o Temp (chiave BAM). Nel report c'è una sezione con gli eventi in ordine di data. |

Ogni elemento riceve un **punteggio** in base a indizi combinati (firma digitale assente o
manomessa, cartella scrivibile dall'utente, nome casuale, file nascosto, comandi offuscati,
download da internet, LOLBins...) e quindi un livello: **Alto**, **Medio** (da verificare),
**Basso**, **Info**. Ogni risultato riporta il motivo, la tecnica MITRE ATT&CK e cosa fare.

Per i dettagli su come si nascondono le backdoor e quale controllo corrisponde a quale
tecnica, leggi [docs/COME-SI-NASCONDONO.md](docs/COME-SI-NASCONDONO.md).

## Come leggere il report

- **Rosso (Alto)**: corrisponde a una tecnica tipica dei malware. Verifica subito.
- **Arancione (Medio)**: spesso legittimo (molti programmi non sono firmati o vivono in
  AppData), ma controlla di riconoscerlo.
- **Blu (Basso) / Grigio (Info)**: per completezza.

Per ogni file sospetto c'è il link per cercarlo su VirusTotal tramite il suo SHA-256.

Gli elementi che hai verificato e sono legittimi si nascondono aggiungendoli a
`allowlist.local.json` (percorsi con `*`, hash SHA-256 o titoli). Crealo copiando
`allowlist.json`: il file `.local` è escluso da git, così la tua lista personale non
finisce mai nella repository, come la cartella `report\`.

```json
{
    "paths": ["C:\\Users\\*\\AppData\\Local\\Discord\\*"],
    "sha256": ["0123ABCD..."],
    "titles": ["*Steam*"]
}
```

## Se trovi qualcosa

1. Non cancellare subito: annota il percorso e verifica il file su virustotal.com.
2. Se è confermato malevolo, scollega il PC da internet.
3. Esegui **Microsoft Defender Offline** e un secondo scanner (Malwarebytes, ESET Online Scanner).
4. Rimuovi prima le voci di avvio (attività, chiave Run, servizio), poi i file.
5. Da un **altro dispositivo** cambia le password (email per prima) e attiva la verifica in due passaggi.
6. Nel dubbio, reinstalla Windows: è l'unico modo per essere certi.

## Se l'antivirus blocca CheckBackdoor

Per trovare un malware, CheckBackdoor legge gli stessi punti del sistema che legge un malware:
le chiavi di avvio, le estensioni dei browser, i file di Discord e dei wallet. E i suoi file
contengono le parole che cerca (comandi offuscati, parametri dei miner...). Alcuni antivirus,
in particolare quelli con analisi del comportamento come Kaspersky, possono scambiarlo per una
minaccia e mettere in quarantena `CheckBackdoor.ps1` o un modulo senza avvisare.

Te ne accorgi perché `Avvia-Scansione.bat`, lo script o l'app ti dicono che manca un file.

1. **Ripristina il file dalla quarantena** dell'antivirus (in Kaspersky: *Rilevamenti* o
   *Quarantena*), oppure scarica di nuovo il progetto. Con git basta `git checkout -- .`.
2. **Aggiungi la cartella alle esclusioni** dell'antivirus. In Kaspersky: *Impostazioni*,
   *Impostazioni di sicurezza*, *Minacce ed esclusioni*, *Gestisci esclusioni*, *Aggiungi*,
   e scegli la cartella di CheckBackdoor. In Microsoft Defender: *Sicurezza di Windows*,
   *Protezione da virus e minacce*, *Gestisci impostazioni*, *Esclusioni*.
3. **Segnala il falso positivo** al produttore dell'antivirus, così migliora per tutti
   (Kaspersky accetta file da analizzare su opentip.kaspersky.com).

Prima di escludere la cartella, controlla di avere scaricato CheckBackdoor dalla sua
repository: il codice è tutto leggibile, ed è il motivo per cui è scritto in PowerShell.
Un'esclusione vale solo per quella cartella: non mettere lì altri file.

## Limiti

CheckBackdoor trova le **tracce** che una backdoor deve lasciare per sopravvivere e comunicare.
Non vede un rootkit kernel già attivo (che può nascondersi al sistema operativo stesso), malware
che vive solo in memoria o uno stealer che ha già rubato i dati e si è cancellato. Non sostituisce
un antivirus: è un secondo parere mirato.

## Struttura

```
CheckBackdoor.ps1        script principale
Azioni.ps1               "Disattiva" con backup e "Annulla" (lo usa l'app)
Avvia-Scansione.bat      avvio con doppio clic
Controlla-File.bat       trascina qui un file per controllarlo prima di aprirlo
allowlist.json           esempio di lista bianca (la tua va in allowlist.local.json)
modules/
  Common.ps1             punteggio di rischio, analisi file e righe di comando
  Persistence.ps1        punti di avvio nel registro e cartelle Esecuzione automatica
  AutorunExtra.ps1       punti di avvio meno noti (profili PowerShell, BITS, Office, Winsock...)
  ScheduledTasks.ps1     attività pianificate
  Services.ps1           servizi e driver
  Wmi.ps1                sottoscrizioni WMI
  Processes.ps1          processi e CPU
  Network.ps1            rete, hosts, proxy, firewall, accesso remoto
  Browser.ps1            estensioni, criteri e collegamenti dei browser
  Injections.ps1         codice iniettato in Discord e nei wallet
  FileCheck.ps1          controllo di un file prima di aprirlo (-File)
  Security.ps1           Defender e difese di Windows
  Accounts.ps1           account e Desktop remoto
  Certificates.ps1       certificati radice
  FileSystem.ps1         file sospetti
  Timeline.ps1           linea temporale dai registri eventi e dalla chiave BAM
  VirusTotal.ps1         verifica opzionale degli hash
  Report.ps1             report HTML/JSON/CSV, confronto, lista bianca
  Remedy.ps1             azioni sulle segnalazioni, con backup e annullamento
app/CheckBackdoor.App/   app con interfaccia (.NET 10, WPF + WebView2)
  ScanRunner.cs          avvia il motore e ne segue gli eventi
  ActionRunner.cs        lancia Azioni.ps1 (come amministratore se serve) e la verifica programmata
  Stores.cs              chiave VirusTotal (DPAPI), elementi ignorati, backup, impostazioni
  ReportStore.cs         storico, riassunti e confronto tra due verifiche
  MainWindow.xaml.cs     finestra, navigazione chiusa, ponte con l'interfaccia
  ui/                    interfaccia in HTML/CSS/JS (fuori dall'app ha dati dimostrativi)
docs/
  COME-SI-NASCONDONO.md  tecniche di occultamento e fonti
  EVENTI.md              formato degli eventi tra motore e app
tests/                   test Pester (vedi "Sviluppo e test")
```

## Sviluppo e test

```powershell
.\tools\Build-Release.ps1      # pacchetti di release in dist\ (test, app, installatore, impronte)
```

- **Prova dei rilevamenti in una macchina virtuale**: `tools\Prova-Rilevamenti.ps1` crea
  persistenze *innocue* (voce Run, attività, servizio, WMI, esclusione di Defender... il cui
  carico è un `Write-Output`), esegue la verifica, dice quali ha trovato e rimuove tutto.
  Rifiuta di partire fuori da una VM. Vedi [docs/VALIDAZIONE.md](docs/VALIDAZIONE.md).
- **Release**: un tag `v1.2.0` prepara su GitHub una release **in bozza** con installatore,
  zip e impronte. Con i segreti `SIGNING_PFX_BASE64` e `SIGNING_PFX_PASSWORD` (un certificato
  di firma del codice di un'autorità riconosciuta) firma exe, script e installatore.

I test usano [Pester](https://pester.dev) 5 o successivo e girano anche su GitHub Actions a ogni
modifica, con Windows PowerShell 5.1 (`.github/workflows/test.yml`).

```powershell
Install-Module Pester -Scope CurrentUser -SkipPublisherCheck   # una volta sola
.\tests\Invoke-Tests.ps1                    # tutti i test (circa un minuto)
.\tests\Invoke-Tests.ps1 -ExcludeTag E2E    # senza le scansioni vere (pochi secondi)
```

| File | Cosa verifica |
|---|---|
| `tests\Common.Tests.ps1` | Percorsi, punteggio di rischio, righe di comando sospette |
| `tests\Report.Tests.ps1` | Accenti, HTML sicuro e offline (i nomi scelti da un attaccante restano testo), lista bianca, confronto tra scansioni |
| `tests\Browser.Tests.ps1` | Estensioni su un profilo Chromium finto, parametri dei collegamenti |
| `tests\FileCheck.Tests.ps1` | Analisi degli eseguibili su file costruiti al volo (doppia estensione, testo invertito, gonfiati, UPX, archivi, DLL sostituite) |
| `tests\Timeline.Tests.ps1` | Linea temporale su eventi finti: servizi spariti, Defender, account, script PowerShell, chiave BAM |
| `tests\AutorunExtra.Tests.ps1` | Cartella Esecuzione automatica spostata, profili PowerShell, uscita di bitsadmin, catalogo Winsock, XML delle attività |
| `tests\Injections.Tests.ps1` | Discord pulito, iniettato e con BetterDiscord; wallet integro e manomesso |
| `tests\Remedy.Tests.ps1` | Disattiva e Annulla su una chiave di prova in HKCU e su file di prova; azioni non ammesse rifiutate |
| `tests\Static.Tests.ps1` | Sintassi, codifica ASCII dove serve, nessuna richiesta di rete fuori da VirusTotal, nessun dato personale nei file pubblicati |
| `tests\EndToEnd.Tests.ps1` | Due scansioni vere con `powershell.exe`, report e confronto |

I campioni di comandi malevoli nei test sono innocui e composti a runtime: scritti per intero
verrebbero bloccati da Microsoft Defender (AMSI) prima ancora di essere eseguiti.

Il piano di sviluppo è in [ROADMAP.md](ROADMAP.md).

### Perché PowerShell

È integrato in Windows (nessuna dipendenza da installare, che sarebbe un'ulteriore superficie
di attacco su un PC forse compromesso), ha accesso nativo a registro, WMI/CIM, firme Authenticode,
Microsoft Defender, Utilità di pianificazione e stack di rete, e il codice è leggibile: puoi
verificare tu stesso che lo scanner non faccia nulla di strano.
