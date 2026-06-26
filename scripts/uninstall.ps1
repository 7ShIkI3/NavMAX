<#
.SYNOPSIS
    Désinstalle NavMAX du système.

.DESCRIPTION
    Supprime l'environnement virtuel, les raccourcis, et les entrées de menu.
    Options pour conserver les données utilisateur et/ou la configuration.

.PARAMETER KeepData
    Conserve le dossier %LOCALAPPDATA%\NavMAX\data\ (DB, logs, fichiers utilisateur).

.PARAMETER KeepConfig
    Conserve le dossier %LOCALAPPDATA%\NavMAX\config\ (fichiers de configuration).

.PARAMETER Force
    Ne pas demander de confirmation.

.EXAMPLE
    .\scripts\uninstall.ps1
    Désinstallation complète (supprime tout).

.EXAMPLE
    .\scripts\uninstall.ps1 -KeepData
    Supprime le venv et les raccourcis, mais conserve les données.

.EXAMPLE
    .\scripts\uninstall.ps1 -KeepData -KeepConfig
    Supprime uniquement le venv et les raccourcis.
#>

param(
    [switch]$KeepData,
    [switch]$KeepConfig,
    [switch]$Force
)

# ─────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppName = "NavMAX"
$AppDir = "$env:LOCALAPPDATA\NavMAX"
$VenvDir = "$AppDir\venv"
$DataDir = "$AppDir\data"
$ConfigDir = "$AppDir\config"
$StaticDir = "$AppDir\static"
$LogDir = "$AppDir\logs"
$ShortcutName = "$AppName Mission Control"
$ShortcutPath = "$env:USERPROFILE\Desktop\$ShortcutName.lnk"
$StartMenuDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\NavMAX"

# ─────────────────────────────────────────────────
# Vérification
# ─────────────────────────────────────────────────
if (-not (Test-Path $AppDir)) {
    Write-Host "⚠  NavMAX n'est pas installé dans $AppDir" -ForegroundColor Yellow
    exit 0
}

if (-not $Force) {
    Write-Host "⚠  Désinstallation de NavMAX" -ForegroundColor Yellow
    $summary = @()
    if ($KeepData) { $summary += "• Conservation des données utilisateur (data/)" }
    if ($KeepConfig) { $summary += "• Conservation de la configuration (config/)" }
    if (-not $KeepData -and -not $KeepConfig) { $summary += "• Suppression COMPLÈTE (données + config)" }
    $summary | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    $choice = Read-Host "Confirmer la désinstallation ? (O/N, défaut: N)"
    if ($choice -eq "" -or $choice -notmatch "^(O|o|Y|y)$") {
        Write-Host "Désinstallation annulée."
        exit 0
    }
}

$Removed = @()
$Kept = @()
$Errors = @()

# ─────────────────────────────────────────────────
# 1. Arrêter les processus NavMAX
# ─────────────────────────────────────────────────
Write-Host "`n[1/6] Arrêt des processus NavMAX..." -ForegroundColor Cyan
$navmaxProcs = Get-Process -Name "python*" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "navmax"
}
foreach ($proc in $navmaxProcs) {
    try {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $Removed += "Processus arrêté (PID $($proc.Id))"
        Write-Host "  ✓ Processus arrêté : PID $($proc.Id)" -ForegroundColor Gray
    } catch {
        Write-Host "  ⚠ Impossible d'arrêter le processus $($proc.Id)" -ForegroundColor Yellow
    }
}
Write-Host "  ✓ Terminé" -ForegroundColor Green

# ─────────────────────────────────────────────────
# 2. Raccourci Bureau
# ─────────────────────────────────────────────────
Write-Host "[2/6] Suppression du raccourci bureau..." -ForegroundColor Cyan
if (Test-Path $ShortcutPath) {
    try {
        Remove-Item $ShortcutPath -Force
        $Removed += "Raccourci bureau : $ShortcutPath"
        Write-Host "  ✓ Raccourci bureau supprimé" -ForegroundColor Green
    } catch {
        $Errors += "Impossible de supprimer le raccourci bureau"
        Write-Host "  ⚠ Erreur : $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⏭ Raccourci bureau introuvable" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────
# 3. Menu Démarrer
# ─────────────────────────────────────────────────
Write-Host "[3/6] Suppression du menu Démarrer..." -ForegroundColor Cyan
if (Test-Path $StartMenuDir) {
    try {
        Remove-Item "$StartMenuDir\*" -Recurse -Force
        Remove-Item $StartMenuDir -Force
        $Removed += "Entrée menu Démarrer : $StartMenuDir"
        Write-Host "  ✓ Entrée menu Démarrer supprimée" -ForegroundColor Green
    } catch {
        $Errors += "Impossible de supprimer l'entrée menu Démarrer"
        Write-Host "  ⚠ Erreur : $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⏭ Menu Démarrer introuvable" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────
# 4. Environnement virtuel et binaires
# ─────────────────────────────────────────────────
Write-Host "[4/6] Suppression de l'environnement virtuel..." -ForegroundColor Cyan
if (Test-Path $VenvDir) {
    try {
        Remove-Item $VenvDir -Recurse -Force
        $Removed += "Environnement virtuel : $VenvDir"
        Write-Host "  ✓ Environnement virtuel supprimé" -ForegroundColor Green
    } catch {
        $Errors += "Impossible de supprimer le venv (peut-être en cours d'utilisation)"
        Write-Host "  ⚠ Erreur : $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⏭ Environnement virtuel introuvable" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────
# 5. Nettoyage des fichiers résiduels
# ─────────────────────────────────────────────────
Write-Host "[5/6] Nettoyage des fichiers résiduels..." -ForegroundColor Cyan

# Static (toujours supprimé — régénéré par install)
if (Test-Path $StaticDir) {
    Remove-Item $StaticDir -Recurse -Force
    $Removed += "Fichiers statiques : $StaticDir"
    Write-Host "  ✓ Static supprimé" -ForegroundColor Gray
}

# Logs (toujours supprimés sauf KeepData)
if ((Test-Path $LogDir) -and -not $KeepData) {
    Remove-Item $LogDir -Recurse -Force
    $Removed += "Logs : $LogDir"
    Write-Host "  ✓ Logs supprimés" -ForegroundColor Gray
} elseif ($KeepData -and (Test-Path $LogDir)) {
    $Kept += "Logs (data gardé) : $LogDir"
    Write-Host "  ⏭ Logs conservés (-KeepData)" -ForegroundColor Yellow
}

# Config
if ((Test-Path $ConfigDir) -and -not $KeepConfig) {
    Remove-Item $ConfigDir -Recurse -Force
    $Removed += "Configuration : $ConfigDir"
    Write-Host "  ✓ Configuration supprimée" -ForegroundColor Gray
} elseif ($KeepConfig -and (Test-Path $ConfigDir)) {
    $Kept += "Configuration (gardée) : $ConfigDir"
    Write-Host "  ⏭ Configuration conservée (-KeepConfig)" -ForegroundColor Yellow
}

# Data
if ((Test-Path $DataDir) -and -not $KeepData) {
    Remove-Item $DataDir -Recurse -Force
    $Removed += "Données utilisateur : $DataDir"
    Write-Host "  ✓ Données supprimées" -ForegroundColor Gray
} elseif ($KeepData -and (Test-Path $DataDir)) {
    $Kept += "Données utilisateur (gardées) : $DataDir"
    Write-Host "  ⏭ Données conservées (-KeepData)" -ForegroundColor Yellow
}

# Icône et launch.bat
$IconPath = "$AppDir\navmax.ico"
$LaunchPath = "$AppDir\launch.bat"
foreach ($f in @($IconPath, $LaunchPath)) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        $Removed += "Fichier : $f"
    }
}

# Dossier AppDir si vide
if (Test-Path $AppDir) {
    $remaining = Get-ChildItem $AppDir -Recurse -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item $AppDir -Force
        $Removed += "Dossier application : $AppDir"
    }
}

# ─────────────────────────────────────────────────
# 6. Vérification finale
# ─────────────────────────────────────────────────
Write-Host "[6/6] Vérification finale..." -ForegroundColor Cyan
$stillExists = Test-Path $AppDir
if ($stillExists -and -not $KeepData -and -not $KeepConfig) {
    Write-Host "  ⚠ Certains fichiers résiduels peuvent subsister dans $AppDir" -ForegroundColor Yellow
} elseif (-not $stillExists) {
    Write-Host "  ✓ Dossier $AppDir complètement supprimé" -ForegroundColor Green
} elseif ($stillExists -and ($KeepData -or $KeepConfig)) {
    Write-Host "  ✓ Dossier $AppDir partiellement conservé (options actives)" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────
# Résumé
# ─────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅ Désinstallation terminée !" -ForegroundColor Green
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan

if ($Removed.Count -gt 0) {
    Write-Host "`n🗑  Éléments supprimés :" -ForegroundColor Red
    $Removed | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
}
if ($Kept.Count -gt 0) {
    Write-Host "`n📦  Éléments conservés :" -ForegroundColor Yellow
    $Kept | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
}
if ($Errors.Count -gt 0) {
    Write-Host "`n⚠  Erreurs :" -ForegroundColor Red
    $Errors | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
}
Write-Host "" -ForegroundColor White
if ($KeepData -or $KeepConfig) {
    Write-Host "  Pour une désinstallation complète, relancez sans -KeepData ni -KeepConfig" -ForegroundColor Gray
}
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
