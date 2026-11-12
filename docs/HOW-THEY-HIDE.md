# Come si nascondono le backdoor (e come le cerca CheckBackdoor)

Una backdoor deve fare tre cose: **restare** sul PC dopo il riavvio, **non farsi notare** e
**comunicare** con chi la controlla. Ognuna di queste lascia tracce: CheckBackdoor cerca quelle.
I codici `Txxxx` sono le tecniche del framework [MITRE ATT&CK](https://attack.mitre.org), il
catalogo di riferimento delle tecniche usate dagli attaccanti.

## Cosa arriva di solito con crack, keygen e giochi pirata

| Famiglia | Cosa fa | Tracce tipiche |
|---|---|---|
| **Cryptominer** (XMRig e derivati) | Usa CPU/GPU per minare criptovalute | Attività pianificata, CPU alta a riposo, esclusioni di Defender, connessioni su porte 3333/14444 |
| **Infostealer** (RedLine, Lumma, Vidar...) | Ruba password, cookie e wallet dal browser, poi spesso si cancella | Spesso **nessuna traccia persistente**: rilevamenti passati di Defender, file in Temp |
| **RAT** (AsyncRAT, njRAT, Remcos, Quasar, NetSupport) | Controllo remoto completo: schermo, webcam, tastiera, file | Chiave Run o attività pianificata, connessione costante verso un IP, porte note |
| **Loader / dropper** | Scarica altri malware in un secondo momento | PowerShell con `-EncodedCommand`, `mshta`, `certutil`, script VBS in AppData |
| **Crackonosh** | Miner che disattiva Defender riavviando in Modalità provvisoria | Servizi in `SafeBoot`, Windows Update rimosso, flag `safeboot` nel BCD |

Il primo segnale è quasi sempre lo stesso: **il crack chiede di disattivare l'antivirus o di
escludere una cartella**. Da quel momento qualunque cosa contenga passa senza controlli.

## Tecniche di persistenza (restare dopo il riavvio)

| Tecnica | Dove | Controllo | Modulo |
|---|---|---|---|
| Chiavi Run/RunOnce | `HK*\...\CurrentVersion\Run` | Analizza ogni voce: firma, percorso, comando | Persistence |
| Cartella Esecuzione automatica | `shell:startup` | File e collegamenti, risolve i `.lnk` | Persistence |
| Attività pianificate (T1053.005) | Utilità di pianificazione | Analizza tutte le azioni, anche in `\Microsoft\` | ScheduledTasks |
| Attività nascoste "Tarrask" | Registro `TaskCache\Tree` senza `SD` | Confronta registro e attività visibili | ScheduledTasks |
| Servizi (T1543.003) | `services.msc` | Eseguibile o `ServiceDll` di ogni servizio | Services |
| Driver kernel / rootkit (T1014) | `System32\drivers` | Firma e posizione di ogni driver attivo | Services |
| Sottoscrizioni WMI (T1546.003) | `root\subscription` | Consumer che eseguono comandi/script | Wmi |
| Winlogon Shell/Userinit (T1547.004) | Registro Winlogon | Confronto con i valori di fabbrica | Persistence |
| IFEO Debugger (T1546.012) | `Image File Execution Options` | Dirottamento di programmi, sethc/utilman | Persistence |
| AppInit_DLLs (T1546.010) | Registro | DLL iniettate in ogni processo | Persistence |
| Dirottamento COM (T1546.015) | `HKCU\Software\Classes\CLSID` | CLSID utente che sovrascrivono quelle di sistema | Persistence |
| Pacchetti LSA (T1547.005) | `Control\Lsa` | DLL non standard caricate da lsass | Persistence |
| Netsh helper, Print monitor, Active Setup, BootExecute, AutoRun di cmd, script di logon | Varie chiavi | Analisi del comando | Persistence |
| Cartella Esecuzione automatica spostata | `User Shell Folders\Startup` | Confronto con il percorso predefinito, analisi dei file nella cartella nuova | AutorunExtra |
| Profili PowerShell (T1546.013) | `profile.ps1` di sistema e di ogni utente | Righe che scaricano, decodificano o disattivano AMSI | AutorunExtra |
| Processi BITS (T1197) | `bitsadmin /list` | Processi con un comando di notifica | AutorunExtra |
| AppCertDlls (T1546.009), database di compatibilità (T1546.011) | `Session Manager\AppCertDlls`, `AppCompatFlags\InstalledSDB` | DLL caricate in altri processi, SDB fuori da AppPatch | AutorunExtra |
| Office (T1137) | Chiave "Office test", componenti aggiuntivi, `XLSTART`, `Word\STARTUP` | DLL e file aperti a ogni avvio di Office | AutorunExtra |
| Provider Winsock | `WinSock2\Parameters` | DLL non Microsoft caricate da ogni programma che usa la rete | AutorunExtra |
| Attività solo come XML | `System32\Tasks` | File di attività che Windows non elenca | ScheduledTasks |
| Backdoor accessibilità (T1546.008) | `sethc.exe`, `utilman.exe` | Firma e hash confrontati con cmd.exe | Security |

## Tecniche di occultamento (non farsi notare)

- **Travestimento (T1036)**: nomi come `svchost.exe` fuori da System32, o quasi identici
  (`svch0st.exe`, `scvhost.exe`). CheckBackdoor controlla percorso, distanza tra i nomi e
  processo genitore (il vero `svchost.exe` è avviato solo da `services.exe`).
- **Cartelle utente**: `AppData`, `Temp`, `ProgramData`, `Users\Public` sono scrivibili senza
  privilegi. Eseguibili non firmati lì, soprattutto nella radice, sono sospetti.
- **Attributi nascosti e flussi ADS (T1564)**: file con attributo nascosto/sistema e dati
  nascosti "dentro" un altro file (Alternate Data Streams).
- **Nomi casuali** (`xkqzvbte.exe`, `a8f3c1d9.exe`), tipici dei dropper.
- **LOLBins (T1218)**: usare programmi Microsoft legittimi (`mshta`, `rundll32`, `regsvr32`,
  `certutil`, `bitsadmin`, `powershell`) per eseguire il codice. Il file è firmato Microsoft,
  quindi CheckBackdoor analizza la **riga di comando** e il file passato come argomento.
- **Comandi offuscati**: PowerShell con `-EncodedCommand`, `-WindowStyle Hidden`, `IEX`,
  `FromBase64String`.
- **Indebolire le difese (T1562)**: esclusioni di Defender, protezione in tempo reale spenta,
  criteri di gruppo, Windows Update disattivato, file `hosts` che blocca siti di antivirus,
  UAC disattivato, firewall spento.
- **Miner "furbi"**: si fermano quando apri Gestione attività. CheckBackdoor misura la CPU senza
  aprirla.

## Il browser: dove finiscono le password

Molti malware dei crack non restano come programma, ma come **estensione del browser** (T1176):
vedono ogni pagina, leggono i cookie di sessione (con cui si entra negli account senza password)
e possono sostituire gli indirizzi dei wallet nelle pagine.

| Tecnica | Come si nasconde | Controllo |
|---|---|---|
| Estensione caricata da cartella | Modalità sviluppatore o `--load-extension` nel collegamento: nessuna revisione dello store | Origine "cartella" o "riga di comando", collegamenti con parametri |
| Estensione imposta da criterio | `ExtensionInstallForcelist`: il pulsante Rimuovi è bloccato e compare "Gestito dalla tua organizzazione" | Criteri di Chrome, Edge, Brave e Firefox nel registro |
| Estensione ritirata dallo store | Era nello store, poi è stata rimossa per malware, ma resta installata | Il campo con cui il browser la marca come dannosa |
| Server di aggiornamento privato | Si aggiorna da un server dell'attaccante e può cambiare codice in qualsiasi momento | `update_url` diverso dagli store ufficiali |
| Controllo remoto del browser | Gli stealer recenti avviano il browser con `--remote-debugging-port` per leggere i cookie aggirando la cifratura | Processi e collegamenti del browser con quel parametro |
| Dirottamento della ricerca | Un criterio impone motore di ricerca, pagina iniziale o proxy | Criteri `DefaultSearchProvider*`, `HomepageLocation`, `Proxy*` |

## Prima ancora di aprirlo: i trucchi nel file

Molti di questi trucchi si vedono **prima** di eseguire il file (`Controlla-File.bat`):

| Trucco | A cosa serve | Controllo |
|---|---|---|
| Doppia estensione (`foto.jpg.exe`) e carattere che inverte il testo (U+202E) | Far sembrare un programma un'immagine o un documento | Nome del file |
| Compressori e protettori (UPX, Themida, VMProtect) | Nascondere il codice agli antivirus | Nomi ed entropia delle sezioni |
| File gonfiato di zeri fino a centinaia di MB | Superare i limiti di dimensione di antivirus e VirusTotal: il file non viene analizzato | Dati accodati con entropia vicina a zero |
| Archivio con un collegamento `.lnk` o uno script | L'utente "apre il documento" e invece lancia PowerShell | Contenuto dello zip, destinazione del collegamento |
| DLL di Windows non firmata accanto al gioco (`version.dll`, `winmm.dll`, `dinput8.dll`) | Il gioco carica la DLL dell'attaccante al posto di quella di sistema (T1574.002) | DLL con nomi di sistema senza firma nella cartella |
| DLL del client di gioco sostituita (`steam_api64.dll`) | È il cuore del crack, e gira a ogni avvio: chi l'ha modificata può aggiungere altro codice | Firma della DLL |

## Dentro le app: le iniezioni degli stealer (T1554)

Alcuni stealer non lasciano un programma da avviare: **modificano il codice di un'app che usi già**,
che da quel momento lo esegue da sola.

- **Discord**: `discord_desktop_core\index.js` normalmente contiene una sola riga. Gli stealer
  aggiungono codice che invia il token dell'account a un webhook a ogni avvio. Il token basta
  per entrare nell'account senza password, e la modifica sopravvive alla rimozione del malware.
- **Exodus e Atomic Wallet**: viene sostituito `app.asar`, il codice dell'app, per inviare la frase
  di recupero quando la digiti.

CheckBackdoor confronta `index.js` con il contenuto originale (riconoscendo BetterDiscord) e
segnala un `app.asar` modificato dopo l'installazione o che contiene canali per inviare dati
(webhook Discord, bot Telegram, servizi di condivisione).

## Le tracce che restano: la linea temporale

Un malware può cancellare i propri file dopo essersi installato, ma Windows annota molte
cose nei suoi registri. CheckBackdoor legge gli ultimi 30 giorni:

- **Servizi installati (evento 7045)**: uno strumento di accesso remoto che si installa come
  servizio, esegue un comando e si rimuove lascia comunque questo evento.
- **Defender (5001, 5007, 1116-1119)**: quando è stato spento, quali esclusioni sono state
  aggiunte e quali minacce ha trovato, con l'esito.
- **Account (4720, 4732)**: account creati o aggiunti agli amministratori (serve
  l'amministratore per leggerli).
- **Script PowerShell (4104)**: Windows registra da solo gli script con parole chiave
  sospette, anche senza alcuna configurazione.
- **Chiave BAM**: l'ultima esecuzione di ogni programma, per utente. Mostra cosa è partito da
  Download, Desktop o Temp, anche se il file ora non c'è più.

Gli eventi rumorosi restano fuori: driver firmati che si reinstallano a ogni avvio (VPN,
anti-cheat) e i moduli che Windows genera per i propri comandi.

## Tecniche di comunicazione e accesso remoto

- **Connessioni C2 (T1071)**: programmi non firmati in cartelle utente connessi a IP pubblici,
  porte di default di RAT noti (4444, 5552, 6606/7707/8808, 2404...), interpreti di comandi
  con connessioni aperte.
- **Backdoor "bind" (T1571)**: un programma in ascolto su una porta aspetta l'attaccante.
- **Strumenti di controllo remoto (T1219)**: AnyDesk, TeamViewer, RustDesk, NetSupport,
  ScreenConnect... legittimi ma spesso installati di nascosto.
- **Desktop remoto forzato**: RDP Wrapper su Windows Home, `ServiceDll` di TermService modificata.
- **Account nascosti (T1136)**: amministratori nascosti dalla schermata di accesso.
- **Proxy e certificati radice (T1090, T1553.004)**: per intercettare il traffico HTTPS.

## Cosa CheckBackdoor NON può vedere

- Un **rootkit kernel già attivo** può mentire al sistema operativo stesso: per quello serve
  una scansione dall'esterno (Microsoft Defender Offline, disco di avvio antivirus).
- **Malware solo in memoria** che non ha ancora scritto nulla su disco.
- **Stealer già "andati via"**: rubano i dati in pochi secondi e si cancellano. Se il crack era
  uno stealer, l'unico rimedio è cambiare le password da un dispositivo pulito.
- **Backdoor nel firmware/BIOS** (molto rare per malware "comune").

## Fonti

- MITRE ATT&CK – Persistence (TA0003) e Defense Evasion (TA0005): https://attack.mitre.org
- MITRE ATT&CK T1546.012 (IFEO): https://attack.mitre.org/techniques/T1546/012
- Elastic – rilevamento del dirottamento COM: https://www.elastic.co/guide/en/security/8.5/component-object-model-hijacking.html
- Gridinsoft – pericoli dei software crackati: https://blog.gridinsoft.com/5-dangers-cracked-software/
- Gridinsoft – IFEO hijack: https://blog.gridinsoft.com/image-file-execution-options-hijack/
- Hackread – Crackonosh nei giochi pirata: https://www.hackread.com/pirated-games-malware-disable-windows-defender/
- Tria.ge – analisi di un miner XMRig distribuito come crack: https://tria.ge/240626-lhyhma1cmj
- ManageEngine – Masquerading T1036: https://www.manageengine.com/log-management/mitre-attack/defense-evasion/masquerading.html
- LOLBAS Project: https://lolbas-project.github.io
