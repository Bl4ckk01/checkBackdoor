# Misurare i rilevamenti in una macchina virtuale

`tools\Prova-Rilevamenti.ps1` risponde alla domanda "CheckBackdoor trova davvero queste
tecniche?" su un Windows vero, senza usare malware.

## Cosa fa

1. Controlla di girare in una macchina virtuale (altrimenti si ferma senza toccare nulla).
2. Crea tecniche di persistenza **innocue**, tutte con il marcatore `CBProva`:

   | Tecnica | MITRE | Serve l'amministratore |
   |---|---|---|
   | Voce Run (HKCU) con PowerShell nascosto e comando in Base64 | T1547.001 | no |
   | Script nella cartella Esecuzione automatica | T1547.001 | no |
   | Attività pianificata con PowerShell nascosto | T1053.005 | no |
   | Profilo PowerShell che scarica ed esegue | T1546.013 | no |
   | Processo BITS con comando di notifica | T1197 | no |
   | Debugger IFEO su un programma | T1546.012 | sì |
   | Servizio che lancia PowerShell nascosto | T1543.003 | sì |
   | Sottoscrizione WMI permanente | T1546.003 | sì |
   | Esclusione di Microsoft Defender | T1562.001 | sì |

   Il "carico" è un `Write-Output`. Nessuna voce viene eseguita: l'attività parte nel 2099,
   il servizio è manuale, il filtro WMI scatta solo nel 2099, il processo BITS punta a un
   indirizzo `.invalid`.
3. Esegue CheckBackdoor e cerca ogni tecnica tra le segnalazioni.
4. **Rimuove sempre tutto**, anche se la verifica fallisce (il profilo PowerShell torna
   identico a prima).
5. Scrive una tabella in `report\validazione\validazione_<data>.md`.

## Come usarlo

1. Crea una macchina virtuale con Windows 10 o 11 (Hyper-V, VirtualBox, VMware) e fai uno
   snapshot.
2. Copia la cartella di CheckBackdoor nella VM.
3. Apri PowerShell **come amministratore** e lancia:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\Prova-Rilevamenti.ps1
   ```

4. Ripeti in una VM con Windows in inglese: alcune parti leggono testi di Windows.
5. Torna allo snapshot.

Il codice di uscita è `0` se tutte le tecniche provate sono state rilevate, `1` se qualcuna
no, `2` se il PC non sembra una macchina virtuale.

## Risultati

Da compilare con le tabelle delle prove. Per ogni sistema: versione di Windows, lingua,
amministratore sì/no, e la tabella prodotta dallo script.

| Sistema | Lingua | Tecniche rilevate | Note |
|---|---|---|---|
| Windows 11 | italiano | da provare | |
| Windows 11 | inglese | da provare | |
| Windows 10 | italiano | da provare | |
