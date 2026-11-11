@echo off
rem Doppio clic per avviare la scansione. Lo script chiedera' i privilegi di
rem amministratore e aprira' il report nel browser al termine.
if not exist "%~dp0CheckBackdoor.ps1" (
    echo.
    echo   Manca CheckBackdoor.ps1 accanto a questo file.
    echo   Di solito lo ha messo in quarantena l'antivirus: CheckBackdoor legge gli stessi
    echo   punti del sistema che legge un malware, per cercarlo, e alcuni antivirus lo
    echo   scambiano per uno di loro. Vedi "Se l'antivirus blocca CheckBackdoor" nel README.
    echo.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CheckBackdoor.ps1" %*
