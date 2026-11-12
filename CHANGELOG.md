# Novità

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/). Le versioni di
motore e app coincidono.

## Non ancora rilasciato

### Sicurezza
- **Installazione in Program Files** (serve l'amministratore): il motore viene eseguito come
  amministratore, quindi non deve stare in una cartella che un programma dell'utente può
  modificare. PowerShell viene avviato con il percorso completo.
- **Backup protetti**: le modifiche fatte come amministratore salvano il backup in
  `%ProgramData%\CheckBackdoor\backup`, scrivibile solo dagli amministratori, e "Annulla" con
  quei privilegi ripristina solo i backup di quella cartella. Un file spostato torna al suo
  posto solo se la sua impronta SHA-256 è quella salvata.
- **"Disattiva"** mostra l'elemento che verrà davvero modificato, non tocca i servizi
  dell'antivirus installato e rifiuta una richiesta cambiata dopo la conferma (`-RequestSha256`).
- **Lista bianca**: le regole troppo ampie (`*`, `*.exe`, intere cartelle utente o di sistema)
  non vengono applicate e sono segnalate; un elemento ignorato dall'app torna visibile se il
  file cambia; il report elenca tutto ciò che la lista bianca ha nascosto, con la regola.
- **Content-Security-Policy** nel report e nell'interfaccia: girano solo gli script di
  CheckBackdoor.
- **Release**: action di GitHub fissate al commit e attestazione di provenienza dei file.

## 1.2.0

### Aggiunto
- **Linea temporale** degli ultimi 30 giorni dai registri di Windows: servizi installati e poi
  rimossi, Defender spento o con nuove esclusioni, minacce trovate, account creati o resi
  amministratori, script PowerShell sospetti, programmi avviati da Download e Temp.
- **Punti di avvio meno noti**: cartella Esecuzione automatica spostata, profili PowerShell,
  processi BITS con un comando, AppCertDlls, database di compatibilità, componenti aggiuntivi e
  chiave "Office test", provider Winsock, attività presenti solo come file XML.
- **App**: storico e confronto tra verifiche (nuove, sparite, comparse, modificate, rimosse);
  impostazioni con chiave di VirusTotal cifrata (DPAPI), verifica programmata settimanale,
  elementi ignorati; azioni su ogni segnalazione: mostra il file, ignora, **disattiva** con
  backup e **Annulla** (`Azioni.ps1`).
- Messaggi chiari quando l'antivirus mette in quarantena un file di CheckBackdoor (codice di
  uscita 4) e una sezione del README su come ripristinarlo.
- Installatore per l'utente, app portatile, pacchetto dello script, impronte SHA-256 e firma
  facoltativa (`tools\Build-Release.ps1`); release in bozza da GitHub Actions.
- `tools\Prova-Rilevamenti.ps1` per misurare i rilevamenti in una macchina virtuale.
- README in inglese.

### Cambiato
- I servizi firmati che si reinstallano a ogni avvio (VPN, anti-cheat) non riempiono più la
  linea temporale.
- I database di compatibilità installati in AppPatch sono "basso rischio" (IIS Express ne
  installa due).

## 1.1.0

### Aggiunto
- Report HTML ridisegnato ("Verifica integrità"), offline, con tema chiaro e scuro.
- Controllo delle estensioni dei browser e delle iniezioni in Discord e nei wallet.
- Controllo di un file prima di aprirlo (`-File`, `Controlla-File.bat`).
- Eventi strutturati della scansione (`-EventsFile`, [docs/EVENTI.md](docs/EVENTI.md)) e
  annullamento.
- Prima versione dell'app con interfaccia (WPF + WebView2).
- Test Pester, controlli di privacy e GitHub Actions.
