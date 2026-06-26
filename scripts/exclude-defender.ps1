# NavMAX — Windows Defender Exclusions
# Exécuter en tant qu'administrateur dans PowerShell
# Usage: powershell -ExecutionPolicy Bypass -File exclude-defender.ps1
# Supprimer: powershell -ExecutionPolicy Bypass -File exclude-defender.ps1 -Remove

param(
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# Vérifier droits admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
if (-not $isAdmin) {
    Write-Host '❌ Ce script nécessite des droits administrateur.' -ForegroundColor Red
    Write-Host "   Relance: clic droit -> 'Exécuter en tant qu'administrateur'" -ForegroundColor Yellow
    exit 1
}

# ── Chemins à exclure ──
$ProjectRoot = if ($PSScriptRoot) {
    Resolve-Path "$PSScriptRoot\.."
} else {
    "$env:USERPROFILE\hermes_knowledge\NavMAX"
}

$Paths = @(
    $ProjectRoot,
    "$env:LOCALAPPDATA\NavMAX",
    "$env:LOCALAPPDATA\Programs\Python",
    "$env:USERPROFILE\hermes_knowledge",
    "$env:APPDATA\Python"
)

$Extensions = @('.ps1', '.py', '.exe', '.bat', '.dll', '.yml', '.yaml')

$Processes = @(
    'python.exe',
    'pythonw.exe',
    'nmap.exe',
    'nuclei.exe',
    'mitmproxy.exe',
    'mitmdump.exe',
    'hashcat.exe',
    'celery.exe',
    'redis-server.exe',
    'ollama.exe',
    'ollama_llama_server.exe'
)

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  NavMAX - Defender Exclusions' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

if ($Remove) {
    Write-Host '>>> Mode: SUPPRESSION des exclusions' -ForegroundColor Yellow
} else {
    Write-Host '>>> Mode: AJOUT des exclusions' -ForegroundColor Green
}

# ── Chemins ──
Write-Host "`n[1/3] Chemins..." -ForegroundColor Cyan
$countPath = 0

foreach ($p in $Paths) {
    $resolved = @(Get-Item $p -ErrorAction SilentlyContinue)
    if (-not $resolved) {
        Write-Host "  skip  $p (introuvable)" -ForegroundColor Gray
        continue
    }
    foreach ($r in $resolved) {
        $path = $r.FullName
        if ($Remove) {
            try {
                Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
                Write-Host "  DEL   $path" -ForegroundColor Red
                $countPath++
            } catch {
                Write-Host "  ?     $path (pas dans les exclusions)" -ForegroundColor Yellow
            }
        } else {
            try {
                Add-MpPreference -ExclusionPath $path -ErrorAction Stop
                Write-Host "  ADD   $path" -ForegroundColor Green
                $countPath++
            } catch {
                Write-Host "  ERR   $path : $_" -ForegroundColor Red
            }
        }
    }
}

# ── Extensions ──
Write-Host "`n[2/3] Extensions..." -ForegroundColor Cyan
$countExt = 0

foreach ($ext in $Extensions) {
    if ($Remove) {
        try {
            Remove-MpPreference -ExclusionExtension $ext -ErrorAction Stop
            Write-Host "  DEL   $ext" -ForegroundColor Red
            $countExt++
        } catch {
            Write-Host "  ?     $ext (pas dans les exclusions)" -ForegroundColor Yellow
        }
    } else {
        try {
            Add-MpPreference -ExclusionExtension $ext -ErrorAction Stop
            Write-Host "  ADD   $ext" -ForegroundColor Green
            $countExt++
        } catch {
            Write-Host "  ERR   $ext : $_" -ForegroundColor Red
        }
    }
}

# ── Processus ──
Write-Host "`n[3/3] Processus..." -ForegroundColor Cyan
$countProc = 0

foreach ($proc in $Processes) {
    if ($Remove) {
        try {
            Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  DEL   $proc" -ForegroundColor Red
            $countProc++
        } catch {
            Write-Host "  ?     $proc (pas dans les exclusions)" -ForegroundColor Yellow
        }
    } else {
        try {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  ADD   $proc" -ForegroundColor Green
            $countProc++
        } catch {
            Write-Host "  ERR   $proc : $_" -ForegroundColor Red
        }
    }
}

# ── Résumé ──
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host '  Termine' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Cyan

if ($Remove) {
    Write-Host "  Supprimes : $countPath chemins, $countExt extensions, $countProc processus" -ForegroundColor Yellow
} else {
    Write-Host "  Ajoutes   : $countPath chemins, $countExt extensions, $countProc processus" -ForegroundColor Green
}

if (-not $Remove) {
    $prefs = Get-MpPreference
    Write-Host "`nVerification - exclusions actives :" -ForegroundColor Cyan
    Write-Host "  Chemins    : $($prefs.ExclusionPath.Count)" -ForegroundColor Gray
    Write-Host "  Extensions : $($prefs.ExclusionExtension.Count)" -ForegroundColor Gray
    Write-Host "  Processus  : $($prefs.ExclusionProcess.Count)" -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Si Defender continue a bloquer :' -ForegroundColor Yellow
    Write-Host '  Get-MpThreatDetection | Remove-MpThreat' -ForegroundColor Gray
    Write-Host '  Restart-Service WinDefend' -ForegroundColor Gray
}
