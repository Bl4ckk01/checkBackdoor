@echo off
rem Drag a file (or a folder) onto this .bat to check it BEFORE opening it.
rem The file is only read, never run. No administrator rights needed.
if "%~1"=="" (
    echo.
    echo   Drag a file or a folder onto Check-File.bat to check it
    echo   before opening it.
    echo.
    pause
    exit /b
)
if not exist "%~dp0CheckBackdoor.ps1" (
    echo.
    echo   CheckBackdoor.ps1 is missing next to this file.
    echo   Usually the antivirus quarantined it: CheckBackdoor reads the same places
    echo   of the system that malware reads, in order to look for it, and some antivirus
    echo   products mistake it for malware. See "If your antivirus blocks CheckBackdoor"
    echo   in the README.
    echo.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CheckBackdoor.ps1" -File "%~1" -PauseAtEnd
