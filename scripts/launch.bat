@echo off
title NavMAX Mission Control
setlocal enabledelayedexpansion

:: ─────────────────────────────────────────────────
:: NavMAX — Launch script
:: Lance le serveur NavMAX et ouvre le navigateur
:: ─────────────────────────────────────────────────

set "APP_DIR=%LOCALAPPDATA%\NavMAX"
set "VENV_DIR=%APP_DIR%\venv"
set "PYTHONW=%VENV_DIR%\Scripts\pythonw.exe"
set "PYTHON=%VENV_DIR%\Scripts\python.exe"
set "PORT=8443"

:: Lire le port depuis config.yaml si disponible
if exist "%APP_DIR%\config\config.yaml" (
    for /f "tokens=2 delims=: " %%a in ('findstr /b "api_port:" "%APP_DIR%\config\config.yaml"') do set "PORT=%%a"
)

:: Vérifier que le venv existe
if not exist "%PYTHON%" (
    echo.
    echo [ERREUR] Environnement virtuel introuvable !
    echo.
    echo Lancer d'abord : scripts\install.ps1
    echo.
    pause
    exit /b 1
)

:: Vérifier que navmax est installé
"%PYTHON%" -c "import navmax" 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERREUR] Le package NavMAX n'est pas installé dans le venv.
    echo.
    echo Relancez : scripts\install.ps1
    echo.
    pause
    exit /b 1
)

echo ═══════════════════════════════════════
echo   NavMAX Mission Control
echo ═══════════════════════════════════════
echo.
echo   Port    : %PORT%
echo   Venv    : %VENV_DIR%
echo.
echo   Demarrage du serveur...
echo.

:: Lancer le serveur avec pythonw (sans console)
start "" /B "%PYTHONW%" -m navmax serve --port %PORT%

:: Attendre que le serveur soit prêt — timeout 5s
timeout /t 3 /nobreak >nul

:: Ouvrir le navigateur
start http://127.0.0.1:%PORT%/dashboard

echo   Dashboard : http://127.0.0.1:%PORT%/dashboard
echo.
echo   Pour arreter le serveur :
echo     - Fermez la fenetre pythonw dans le gestionnaire de taches
echo     - Ou utilisez : taskkill /f /im pythonw.exe
echo.
echo   Le serveur tourne en arriere-plan.
echo   Appuyez sur une touche pour fermer ce message...
pause >nul
