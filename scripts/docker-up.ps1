<#
.SYNOPSIS
    NavMAX — Docker Compose Startup Script (Windows)
.DESCRIPTION
    Vérifie Docker, crée les dossiers, copie .env si nécessaire,
    puis lance docker compose up -d.
.NOTES
    Usage : .\scripts\docker-up.ps1
#>

Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          NavMAX — Démarrage Production              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Vérifier que Docker est installé ──────────────────────────────
$dockerPath = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerPath) {
    Write-Host "❌ Docker n'est pas installé." -ForegroundColor Red
    Write-Host "   https://docs.docker.com/get-docker/"
    exit 1
}
Write-Host "✓ Docker trouvé : $(docker --version)" -ForegroundColor Green

# ── Vérifier Docker Compose ───────────────────────────────────────
$composeVersion = docker compose version 2>$null
if (-not $composeVersion) {
    Write-Host "❌ Docker Compose n'est pas disponible." -ForegroundColor Red
    exit 1
}
Write-Host "✓ Docker Compose trouvé : $composeVersion" -ForegroundColor Green
Write-Host ""

# ── Se placer à la racine du projet ───────────────────────────────
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
Set-Location $projectDir
Write-Host "📂 Répertoire du projet : $projectDir" -ForegroundColor Cyan

# ── Créer les dossiers nécessaires ────────────────────────────────
if (-not (Test-Path "navmax/static")) { New-Item -ItemType Directory -Path "navmax/static" -Force | Out-Null }
if (-not (Test-Path "nginx")) { New-Item -ItemType Directory -Path "nginx" -Force | Out-Null }
Write-Host "✓ Dossiers vérifiés : static/, nginx/" -ForegroundColor Green

# ── Vérifier .env ─────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  Fichier .env non trouvé. Copie depuis .env.example..." -ForegroundColor Yellow
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "⚠️  ⚠️  ⚠️  IMPORTANT : Éditez .env avec vos propres secrets !" -ForegroundColor Yellow
        Write-Host "   Notamment : NAVMAX_JWT_SECRET, POSTGRES_PASSWORD, REDIS_PASSWORD" -ForegroundColor Yellow
    } else {
        Write-Host "❌ .env.example introuvable. Créez un fichier .env manuellement." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✓ Fichier .env trouvé" -ForegroundColor Green
}

# ── Vérifier la config Nginx ──────────────────────────────────────
if (-not (Test-Path "nginx/nginx.conf")) {
    Write-Host "❌ nginx/nginx.conf introuvable." -ForegroundColor Red
    exit 1
}
Write-Host "✓ Configuration Nginx trouvée" -ForegroundColor Green
Write-Host ""

Write-Host "🚀 Lancement de NavMAX..." -ForegroundColor Cyan
Write-Host ""

# ── Build et démarrage ────────────────────────────────────────────
docker compose up -d --build

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║          NavMAX est en ligne !                       ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

$nginxPort = if ($env:NGINX_PORT) { $env:NGINX_PORT } else { "80" }

Write-Host "   API :       http://localhost:$nginxPort/api/v1/" -ForegroundColor Cyan
Write-Host "   Docs :      http://localhost:$nginxPort/docs" -ForegroundColor Cyan
Write-Host "   Health :    http://localhost:$nginxPort/api/v1/health" -ForegroundColor Cyan
Write-Host ""

# ── Afficher les logs en temps réel ──────────────────────────────
Write-Host "📋 Logs des conteneurs (Ctrl+C pour quitter) :" -ForegroundColor Yellow
Write-Host ""
docker compose logs -f --tail=50
