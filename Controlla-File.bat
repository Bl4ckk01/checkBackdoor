@echo off
rem Trascina un file (o una cartella) sopra questo .bat per controllarlo PRIMA di aprirlo.
rem Il file viene solo letto, mai eseguito. Non servono i privilegi di amministratore.
if "%~1"=="" (
    echo.
    echo   Trascina un file o una cartella sopra Controlla-File.bat per controllarlo
    echo   prima di aprirlo.
    echo.
    pause
    exit /b
)
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CheckBackdoor.ps1" -File "%~1" -PauseAtEnd
