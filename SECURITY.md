# Sicurezza

## Scaricare CheckBackdoor in modo sicuro

Uno strumento che si esegue come amministratore è un bersaglio ideale per copie modificate.

- Scaricalo solo da questa repository GitHub, mai da siti, video o messaggi che lo ripropongono.
- Prima di eseguirlo, confronta l'impronta SHA-256 dell'archivio con quella pubblicata nella
  pagina della release:
  ```powershell
  Get-FileHash .\CheckBackdoor.zip -Algorithm SHA256
  ```
- Il codice è PowerShell leggibile: puoi aprire `CheckBackdoor.ps1` e la cartella `modules\`
  e verificare che non scarichi né invii nulla. L'unica connessione possibile è verso VirusTotal,
  e solo se fornisci tu una chiave API (`-VirusTotalApiKey`).

## Dove tenerlo

Quando chiede i privilegi di amministratore, CheckBackdoor esegue i propri file con quei
privilegi. Se stanno in una cartella che qualsiasi programma può modificare (Download,
Desktop, AppData), un malware già presente sul PC può riscriverli e ottenere i privilegi alla
prossima verifica.

- L'installatore mette il programma in `Program Files`, che solo gli amministratori possono
  modificare: è il modo consigliato.
- Se usi lo zip o gli script, estraili in una cartella protetta allo stesso modo, oppure
  esegui la verifica senza privilegi (`-NoElevate`): sarà meno completa, ma nessun file
  modificabile verrà eseguito come amministratore.
- Le release hanno un'attestazione di provenienza. Per verificare un file scaricato:
  ```powershell
  gh attestation verify .\CheckBackdoor-<versione>-setup.exe --repo <proprietario>/<repository>
  ```

## Cosa non si fida di cosa

- **Lista bianca.** `allowlist.local.json` e gli elementi ignorati dall'app sono file
  dell'utente: un malware può scriverci. Le regole troppo ampie non vengono applicate e
  compaiono tra le segnalazioni, e il report elenca sempre ciò che è stato nascosto.
- **"Disattiva" e "Annulla".** Agiscono solo su chiavi di avvio, cartelle Esecuzione
  automatica, attività non di Windows e servizi non di Microsoft né dell'antivirus. Come
  amministratore i backup si scrivono e si leggono solo in `%ProgramData%\CheckBackdoor\backup`.
- **Report.** I nomi di file e i comandi che contiene li sceglie chi ha scritto il malware:
  sono sempre mostrati come testo, e una Content-Security-Policy blocca ogni altro script.

## Segnalare una vulnerabilità

Se trovi un problema di sicurezza nello scanner, segnalalo in privato con la funzione
"Report a vulnerability" della scheda **Security** di GitHub, non con una issue pubblica.
Ad esempio: un report che esegue codice all'apertura, un percorso che fa leggere o modificare
file a chi non dovrebbe, o un modo per nascondere una persistenza ai controlli.

## Falsi negativi e falsi positivi

Un elemento malevolo non rilevato o un programma legittimo segnalato non sono vulnerabilità:
apri una normale issue, senza allegare il report completo. Il report contiene dati del tuo PC
(nomi utente, percorsi, programmi installati): copia solo la segnalazione interessata.
