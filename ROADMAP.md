# Roadmap

CheckBackdoor cresce in due direzioni: **controlli migliori** per le tracce che backdoor e
stealer lasciano su Windows, e un **software con interfaccia** che sostituisca lo script da
riga di comando senza perdere trasparenza né privacy (nessun dato esce dal PC).

## Fasi

| Fase | Contenuto | Stato |
|---|---|---|
| 0 | Licenza e avviso, test automatici (Pester 5), controllo automatico su GitHub Actions | fatto (GitHub Actions da verificare al primo push) |
| 1 | Il motore emette eventi strutturati (avanzamento e segnalazioni) con formato versionato ([docs/EVENTI.md](docs/EVENTI.md)) | fatto |
| 2 | Controllo di un file prima di aprirlo; iniezioni nei client Discord e nei wallet | fatto |
| 3 | App: Home, Verifica in corso, Risultati (sola lettura) | fatto (anteprima, senza installatore) |
| 4 | Linea temporale dai registri eventi; punti di avvio ancora scoperti | fatto |
| 5 | App: Confronto, Impostazioni, azioni con backup e Annulla, scansione programmata | fatto |
| 6 | Validazione su macchine virtuali, installer firmato, README in inglese, prima release | pronta: mancano le prove nelle VM, il certificato di firma e la pubblicazione |

## Controlli da aggiungere

In ordine di valore per chi scarica crack e giochi da fonti non ufficiali.

1. **Controllo di un file prima di aprirlo** (`-File`):
   - firma digitale e hash su VirusTotal;
   - sito di provenienza (Zone.Identifier);
   - compressione o offuscamento (entropia, sezioni UPX);
   - dati accodati all'eseguibile;
   - DLL con nomi di sistema non firmate nella stessa cartella (caricamento di DLL laterale).
2. **Iniezioni degli stealer:** `index.js` modificato di Discord, `app.asar` di Exodus e Atomic
   Wallet.
3. **Linea temporale:**
   - eventi 7045 (nuovo servizio);
   - 5001 e 5007 (Defender modificato);
   - 1116 e 1117 (rilevamenti);
   - 4720 e 4732 (account e amministratori);
   - 4104 (PowerShell);
   - chiave BAM (ultima esecuzione dei programmi).
4. **Punti di avvio ancora scoperti:**
   - profili PowerShell;
   - cartella Esecuzione automatica spostata tramite `User Shell Folders`;
   - processi BITS;
   - AppCertDlls;
   - database di compatibilità (SDB);
   - componenti aggiuntivi di Office;
   - provider Winsock;
   - attività pianificate presenti solo come XML.
5. **Misura dell'efficacia:**
   - persistenze simulate con Atomic Red Team in una macchina virtuale, con una tabella
     delle tecniche rilevate;
   - prova su Windows 10 e su Windows in inglese.

## Software con interfaccia

- **Tecnologia:** .NET 10 (LTS) con WPF e WebView2. Riusa l'interfaccia del report
  (direzione "Verifica integrità", vedi `DESIGN.md`), produce un solo eseguibile firmabile e
  lascia il motore di scansione in PowerShell.
- **Due processi:** l'interfaccia gira come utente normale. Solo la scansione chiede i
  privilegi di amministratore e trasmette avanzamento e segnalazioni all'interfaccia.
- **Schermate:**
  - Home: ultimo verdetto, avvio della verifica, area per trascinare un file da controllare;
  - Verifica in corso: le aree si spuntano dal vivo;
  - Risultati;
  - Confronto e storico;
  - Impostazioni: chiave VirusTotal cifrata con DPAPI, lista bianca, scansione programmata.
- **Azioni su ogni segnalazione:**
  - apri il percorso;
  - controlla su VirusTotal;
  - ignora (lista bianca);
  - in seguito, "Disattiva": sempre con backup e pulsante Annulla, mai cancellazioni.

## Principi che non cambiano

- Sola lettura per impostazione predefinita; ogni modifica al sistema si può annullare.
- Nessun dato inviato, tranne gli hash a VirusTotal e solo se l'utente lo attiva.
- Ogni segnalazione spiega perché è sospetta e cosa fare.
