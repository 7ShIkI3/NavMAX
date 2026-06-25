#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# NavMAX — Docker Compose Startup Script (Linux / macOS)
# Usage : chmod +x scripts/docker-up.sh && ./scripts/docker-up.sh
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          NavMAX — Démarrage Production              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Vérifier que Docker est installé ──────────────────────────────
if ! command -v docker &>/dev/null; then
    echo -e "${RED}❌ Docker n'est pas installé.${NC}"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker trouvé : $(docker --version)${NC}"

# ── Vérifier que Docker Compose est disponible ────────────────────
if docker compose version &>/dev/null; then
    COMPOSE="docker compose"
elif docker-compose --version &>/dev/null; then
    COMPOSE="docker-compose"
else
    echo -e "${RED}❌ Docker Compose n'est pas installé.${NC}"
    echo "   Vérifiez que docker compose ou docker-compose est disponible."
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose trouvé : $($COMPOSE version)${NC}"
echo ""

# ── Se placer dans le répertoire du projet ────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"
echo -e "${CYAN}📂 Répertoire du projet : $PROJECT_DIR${NC}"

# ── Créer les dossiers nécessaires ────────────────────────────────
mkdir -p navmax/static
mkdir -p nginx
echo -e "${GREEN}✓ Dossiers vérifiés : static/, nginx/${NC}"

# ── Vérifier .env ─────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  Fichier .env non trouvé. Copie depuis .env.example...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${YELLOW}⚠️  ⚠️  ⚠️  IMPORTANT : Éditez .env avec vos propres secrets !${NC}"
        echo -e "${YELLOW}   Notamment : NAVMAX_JWT_SECRET, POSTGRES_PASSWORD, REDIS_PASSWORD${NC}"
    else
        echo -e "${RED}❌ .env.example introuvable. Créez un fichier .env manuellement.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Fichier .env trouvé${NC}"
fi

# ── Vérifier la configuration Nginx ───────────────────────────────
if [ ! -f nginx/nginx.conf ]; then
    echo -e "${RED}❌ nginx/nginx.conf introuvable. Vérifiez que le dossier nginx/ existe.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Configuration Nginx trouvée${NC}"

echo ""
echo -e "${CYAN}🚀 Lancement de NavMAX...${NC}"
echo ""

# ── Build et démarrage ────────────────────────────────────────────
$COMPOSE up -d --build

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          NavMAX est en ligne !                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "   API :       ${CYAN}http://localhost:${NGINX_PORT:-80}/api/v1/${NC}"
echo -e "   Docs :      ${CYAN}http://localhost:${NGINX_PORT:-80}/docs${NC}"
echo -e "   Health :    ${CYAN}http://localhost:${NGINX_PORT:-80}/api/v1/health${NC}"
echo ""

# ── Afficher les logs en temps réel ──────────────────────────────
echo -e "${YELLOW}📋 Logs des conteneurs (Ctrl+C pour quitter) :${NC}"
echo ""
$COMPOSE logs -f --tail=50
