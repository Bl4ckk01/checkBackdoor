@echo off
rem Double-click to start the scan. The script asks for administrator rights
rem and opens the report in the browser when it finishes.
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CheckBackdoor.ps1" %*
