# NavMAX — Windows Defender Exclusions
# Exécuter en tant qu'administrateur dans PowerShell
# Usage: powershell -ExecutionPolicy Bypass -File exclude-defender.ps1

param(
    [switch]$Remove  # Supprimer les exclusions au lieu de les ajouter
)

$ErrorActionPreference = "Stop"

# Vérifier droits admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Ce script nécessite des droits administrateur." -ForegroundColor Red
    Write-Host "   Relance: clic droit → 'Exécuter en tant qu'administrateur'" -ForegroundColor Yellow
    exit 1
}

# ── Chemins à exclure ──
$ProjectRoot = if ($PSScriptRoot) {
    Resolve-Path "$PSScriptRoot\.."
} else {
    $env:USERPROFILE + "\hermes_knowledge\NavMAX"
}

$Paths = @(
    # Projet principal
    $ProjectRoot,
    
    # Installation système
    "$env:LOCALAPPDATA\NavMAX",
    
    # Python venv (pour les dépendances comme impacket, scapy, mitmproxy)
    "$env:LOCALAPPDATA\Programs\Python",
    
    # Hermes skills (contient les modules de pentest)
    "$env:USERPROFILE\hermes_knowledge",
    
    # Pip packages (impacket, scapy, etc.)
    "$env:APPDATA\Python",
    
    # Temp build
    "$env:TEMP\navmax-*",
    "$env:TEMP\pip-*"
)

# ── Extensions à exclure ──
$Extensions = @(
    ".ps1",   # Scripts PowerShell (payloads)
    ".py",    # Python (exploits)
    ".exe",   # Binaires d'outils (nmap, nuclei, mitmproxy)
    ".bat",   # Batch scripts
    ".dll",   # Librairies compilées
    ".yml",   # Configs YAML
    ".yaml"
)

# ── Processus à exclure ──
$Processes = @(
    "python.exe",
    "pythonw.exe",
    "nmap.exe",
    "nuclei.exe",
    "mitmproxy.exe",
    "mitmdump.exe",
    "hashcat.exe",
    "celery.exe",
    "redis-server.exe",
    "ollama.exe",
    "ollama_llama_server.exe"
)

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   NavMAX — Defender Exclusions          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Remove) {
    Write-Host "🗑  Mode: SUPPRESSION des exclusions" -ForegroundColor Yellow
} else {
    Write-Host "🛡️  Mode: AJOUT des exclusions" -ForegroundColor Green
}

# ── Chemins ──
Write-Host "`n📁 Chemins..." -ForegroundColor Cyan
$addedPaths = 0
$removedPaths = 0

foreach ($p in $Paths) {
    # Résoudre les wildcards
    $resolved = @(Get-Item $p -ErrorAction SilentlyContinue)
    if (-not $resolved) {
        Write-Host "  ⏭  $p (introuvable)" -ForegroundColor Gray
        continue
    }
    
    foreach ($r in $resolved) {
        $path = $r.FullName
        
        if ($Remove) {
            try {
                Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
                Write-Host "  ✕  $path" -ForegroundColor Red
                $removedPaths++
            } catch {
                Write-Host "  ⚠  $path — non trouvé dans les exclusions" -ForegroundColor Yellow
            }
        } else {
            try {
                Add-MpPreference -ExclusionPath $path -ErrorAction Stop
                Write-Host "  ✓  $path" -ForegroundColor Green
                $addedPaths++
            } catch {
                Write-Host "  ❌ $path — erreur: $_" -ForegroundColor Red
            }
        }
    }
}

# ── Extensions ──
Write-Host "`n📎 Extensions..." -ForegroundColor Cyan
$addedExt = 0
$removedExt = 0

foreach ($ext in $Extensions) {
    if ($Remove) {
        try {
            Remove-MpPreference -ExclusionExtension $ext -ErrorAction Stop
            Write-Host "  ✕  $ext" -ForegroundColor Red
            $removedExt++
        } catch {
            Write-Host "  ⚠  $ext — non trouvé" -ForegroundColor Yellow
        }
    } else {
        try {
            Add-MpPreference -ExclusionExtension $ext -ErrorAction Stop
            Write-Host "  ✓  $ext" -ForegroundColor Green
            $addedExt++
        } catch {
            Write-Host "  ❌ $ext — erreur: $_" -ForegroundColor Red
        }
    }
}

# ── Processus ──
Write-Host "`n⚙️  Processus..." -ForegroundColor Cyan
$addedProc = 0
$removedProc = 0

foreach ($proc in $Processes) {
    if ($Remove) {
        try {
            Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  ✕  $proc" -ForegroundColor Red
            $removedProc++
        } catch {
            Write-Host "  ⚠  $proc — non trouvé" -ForegroundColor Yellow
        }
    } else {
        try {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  ✓  $proc" -ForegroundColor Green
            $addedProc++
        } catch {
            Write-Host "  ❌ $proc — erreur: $_" -ForegroundColor Red
        }
    }
}

# ── Résumé ──
Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅ Terminé" -ForegroundColor Green
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan

if ($Remove) {
    Write-Host "  Exclusions supprimées : $removedPaths chemins, $removedExt extensions, $removedProc processus" -ForegroundColor Yellow
} else {
    Write-Host "  Exclusions ajoutées  : $addedPaths chemins, $addedExt extensions, $addedProc processus" -ForegroundColor Green
}

# ── Vérification ──
if (-not $Remove) {
    Write-Host "`n🔍 Vérification — exclusions actives :" -ForegroundColor Cyan
    $prefs = Get-MpPreference
    Write-Host "  Chemins    : $($prefs.ExclusionPath.Count)" -ForegroundColor Gray
    Write-Host "  Extensions : $($prefs.ExclusionExtension.Count)" -ForegroundColor Gray
    Write-Host "  Processus  : $($prefs.ExclusionProcess.Count)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "💡 Astuce : Si Defender continue à bloquer, vide le cache :" -ForegroundColor Yellow
    Write-Host "   Get-MpThreatDetection | Remove-MpThreat" -ForegroundColor Gray
    Write-Host "   Restart-Service WinDefend" -ForegroundColor Gray
}
