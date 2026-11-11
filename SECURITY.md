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

## Segnalare una vulnerabilità

Se trovi un problema di sicurezza nello scanner, segnalalo in privato con la funzione
"Report a vulnerability" della scheda **Security** di GitHub, non con una issue pubblica.
Ad esempio: un report che esegue codice all'apertura, un percorso che fa leggere o modificare
file a chi non dovrebbe, o un modo per nascondere una persistenza ai controlli.

## Falsi negativi e falsi positivi

Un elemento malevolo non rilevato o un programma legittimo segnalato non sono vulnerabilità:
apri una normale issue, senza allegare il report completo. Il report contiene dati del tuo PC
(nomi utente, percorsi, programmi installati): copia solo la segnalazione interessata.
