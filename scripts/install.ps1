<#
.SYNOPSIS
    Installe NavMAX sur le système — crée un environnement virtuel, installe les dépendances,
    copie les assets, crée un raccourci bureau et une entrée dans le menu Démarrer.

.DESCRIPTION
    Script d'installation Windows pour NavMAX. Fonctionne sans droits administrateur.
    Installe le projet en mode editable dans %LOCALAPPDATA%\NavMAX\venv\,
    copie les fichiers statiques et la configuration, crée un raccourci bureau
    "NavMAX Mission Control" et une entrée dans le menu Démarrer.

.PARAMETER DevMode
    Active le mode développement (installe avec les dépendances dev, pip install -e ".[dev]").

.PARAMETER Port
    Port du serveur API (défaut: 8443). Modifie le raccourci en conséquence.

.PARAMETER Force
    Force la réinstallation sans confirmation.

.PARAMETER NoShortcut
    Ne pas créer de raccourci bureau.

.PARAMETER NoStartMenu
    Ne pas créer d'entrée dans le menu Démarrer.

.EXAMPLE
    .\scripts\install.ps1
    Installation standard (port 8443).

.EXAMPLE
    .\scripts\install.ps1 -DevMode -Port 8080
    Installation en mode développement sur le port 8080.

.EXAMPLE
    .\scripts\install.ps1 -Force -NoShortcut
    Réinstallation silencieuse sans raccourci bureau.
#>

param(
    [switch]$DevMode,
    [int]$Port = 8443,
    [switch]$Force,
    [switch]$NoShortcut,
    [switch]$NoStartMenu
)

# ─────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
$AppName = "NavMAX"
$AppDir = "$env:LOCALAPPDATA\NavMAX"
$VenvDir = "$AppDir\venv"
$DataDir = "$AppDir\data"
$ConfigDir = "$AppDir\config"
$StaticDir = "$AppDir\static"
$LogDir = "$AppDir\logs"
$IconFile = "$ScriptDir\navmax.ico"
$ShortcutName = "$AppName Mission Control"
$ShortcutPath = "$env:USERPROFILE\Desktop\$ShortcutName.lnk"
$StartMenuDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\NavMAX"
$StartMenuShortcut = "$StartMenuDir\$ShortcutName.lnk"
$StartMenuUninstall = "$StartMenuDir\Désinstaller NavMAX.lnk"
$PythonExe = "python"
$PythonWExe = "pythonw"

# Vérifier si python est accessible
$PythonPath = (Get-Command $PythonExe -ErrorAction SilentlyContinue).Source
if (-not $PythonPath) {
    Write-Error "Python n'est pas trouvé dans le PATH. Installez Python 3.11+ d'abord."
    exit 1
}
Write-Host "✓ Python trouvé : $PythonPath" -ForegroundColor Green

# ─────────────────────────────────────────────────
# Détection d'une installation existante
# ─────────────────────────────────────────────────
$AlreadyInstalled = Test-Path "$VenvDir\pyvenv.cfg"
if ($AlreadyInstalled -and -not $Force) {
    Write-Host "⚠  NavMAX semble déjà installé dans $AppDir" -ForegroundColor Yellow
    $choice = Read-Host "Voulez-vous mettre à jour ? (O/N, défaut: O)"
    if ($choice -ne "" -and $choice -notmatch "^(O|o|Y|y)$") {
        Write-Host "Installation annulée."
        exit 0
    }
    Write-Host "→ Mise à jour de l'installation..." -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────
# Création des répertoires
# ─────────────────────────────────────────────────
Write-Host "`n[1/5] Création des répertoires..." -ForegroundColor Cyan
@($AppDir, $DataDir, $ConfigDir, $StaticDir, $LogDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "  ✓ $_" -ForegroundColor Gray
    }
}

# ─────────────────────────────────────────────────
# Installation de l'environnement virtuel
# ─────────────────────────────────────────────────
Write-Host "[2/5] Installation de l'environnement virtuel..." -ForegroundColor Cyan

# Création du venv
if (Test-Path "$VenvDir\pyvenv.cfg") {
    Write-Host "  ✓ Environnement existant, mise à jour..." -ForegroundColor Gray
    & "$VenvDir\Scripts\python.exe" -m pip install --upgrade pip --quiet 2>&1 | Out-Null
} else {
    & $PythonExe -m venv "$VenvDir"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Échec de la création du venv."
        exit 1
    }
    Write-Host "  ✓ Environnement virtuel créé : $VenvDir" -ForegroundColor Gray
}

$VenvPython = "$VenvDir\Scripts\python.exe"
$VenvPip = "$VenvDir\Scripts\pip.exe"

# Upgrade pip
& $VenvPython -m pip install --upgrade pip --quiet 2>&1 | Out-Null

# Installation du projet
$InstallSpec = if ($DevMode) { ".[dev]" } else { "." }
Write-Host "  Installation du package : pip install -e '$InstallSpec'" -ForegroundColor Gray
& $VenvPip install -e "$ProjectRoot" --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de l'installation du package."
    exit 1
}
Write-Host "  ✓ Package installé en mode editable" -ForegroundColor Green

# ─────────────────────────────────────────────────
# Copie des assets
# ─────────────────────────────────────────────────
Write-Host "[3/5] Copie des assets..." -ForegroundColor Cyan

# Configuration par défaut
$DefaultConfig = "$ConfigDir\config.yaml"
if (-not (Test-Path $DefaultConfig)) {
    @"
# NavMAX — Configuration par défaut
api_host: "127.0.0.1"
api_port: $Port
debug: false
log_level: "info"
db_path: "$($DataDir -replace '\\', '/')/navmax.db"
"@ | Out-File -FilePath $DefaultConfig -Encoding utf8
    Write-Host "  ✓ config.yaml créé" -ForegroundColor Gray
}

# Static files (si le dossier static existe dans le projet)
$ProjectStatic = "$ProjectRoot\navmax\static"  # peut être vide
if (Test-Path $ProjectStatic) {
    Copy-Item "$ProjectStatic\*" "$StaticDir\" -Recurse -Force
    Write-Host "  ✓ Static files copiés" -ForegroundColor Gray
}

# Icône
$IconDest = "$AppDir\navmax.ico"
if (Test-Path $IconFile) {
    Copy-Item $IconFile $IconDest -Force
    Write-Host "  ✓ Icône copiée" -ForegroundColor Gray
}

# Script launch.bat
Copy-Item "$ScriptDir\launch.bat" "$AppDir\" -Force
Write-Host "  ✓ launch.bat copié" -ForegroundColor Gray

# ─────────────────────────────────────────────────
# Raccourci Bureau
# ─────────────────────────────────────────────────
Write-Host "[4/5] Création des raccourcis..." -ForegroundColor Cyan

if (-not $NoShortcut) {
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = "$VenvDir\Scripts\$PythonWExe.exe"
    $Shortcut.Arguments = "-m uvicorn navmax.api.app:app --host 127.0.0.1 --port $Port"
    $Shortcut.WorkingDirectory = $AppDir
    $Shortcut.Description = "$AppName Mission Control - Dashboard cybernetique"
    if (Test-Path $IconDest) {
        $Shortcut.IconLocation = "$IconDest, 0"
    }
    $Shortcut.Save()
    Write-Host "  ✓ Raccourci bureau créé : $ShortcutPath" -ForegroundColor Green
} else {
    Write-Host "  ⏭ Raccourci bureau ignoré (-NoShortcut)" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────
# Menu Démarrer
# ─────────────────────────────────────────────────
if (-not $NoStartMenu) {
    if (-not (Test-Path $StartMenuDir)) {
        New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null
    }

    $WScriptShell = New-Object -ComObject WScript.Shell

    # Lancer NavMAX
    $Shortcut = $WScriptShell.CreateShortcut($StartMenuShortcut)
    $Shortcut.TargetPath = "$VenvDir\Scripts\$PythonWExe.exe"
    $Shortcut.Arguments = "-m uvicorn navmax.api.app:app --host 127.0.0.1 --port $Port"
    $Shortcut.WorkingDirectory = $AppDir
    $Shortcut.Description = "$AppName Mission Control - Dashboard cybernetique"
    if (Test-Path $IconDest) {
        $Shortcut.IconLocation = "$IconDest, 0"
    }
    $Shortcut.Save()

    # Désinstaller
    $Unlink = $WScriptShell.CreateShortcut($StartMenuUninstall)
    $Unlink.TargetPath = "$VenvDir\Scripts\$PythonWExe.exe"
    $Unlink.Arguments = "-m navmax uninstall"
    $Unlink.WorkingDirectory = $AppDir
    $Unlink.Description = "Désinstaller $AppName"
    if (Test-Path $IconDest) {
        $Unlink.IconLocation = "$IconDest, 0"
    }
    $Unlink.Save()

    Write-Host "  ✓ Entrée menu Démarrer créée : $StartMenuDir" -ForegroundColor Green
} else {
    Write-Host "  ⏭ Menu Démarrer ignoré (-NoStartMenu)" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────
# Vérification finale
# ─────────────────────────────────────────────────
Write-Host "[5/5] Vérification..." -ForegroundColor Cyan
$VenvPython = "$VenvDir\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Version = & $VenvPython --version 2>&1
    Write-Host "  ✓ Python : $Version" -ForegroundColor Gray
}
if ((Test-Path "$VenvDir\Lib\site-packages\navmax") -or (Test-Path "$VenvDir\Lib\site-packages\navmax*.egg-link") -or (Test-Path "$VenvDir\Lib\site-packages\navmax*.pth") -or (Test-Path "$VenvDir\Lib\site-packages\*navmax*.pth") -or (Test-Path "$VenvDir\Lib\site-packages\navmax*.dist-info")) {
    Write-Host "  ✓ Package navmax installé" -ForegroundColor Gray
} else {
    Write-Host "  ⚠ Vérifiez que navmax est bien accessible depuis le venv" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────
# Résumé
# ─────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅ Installation terminée !" -ForegroundColor Green
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Application   : $AppName" -ForegroundColor White
Write-Host "  Version       :" (Select-String -Path "$ProjectRoot\pyproject.toml" -Pattern '^version = "(.+)"' | ForEach-Object { $_.Matches.Groups[1].Value }) -ForegroundColor White
Write-Host "  Port          : $Port" -ForegroundColor White
Write-Host "  Environnement : $VenvDir" -ForegroundColor White
Write-Host "  Données       : $DataDir" -ForegroundColor White
Write-Host "  Config        : $DefaultConfig" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "  ▶ Lancer :" -ForegroundColor White
Write-Host "    $AppDir\launch.bat" -ForegroundColor White
Write-Host "    ou : $ShortcutName (Bureau)" -ForegroundColor White
Write-Host "    ou : navmax serve" -ForegroundColor White
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
