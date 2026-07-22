#!/bin/bash
# Wrapper for Dark Triad server with proper API key
source /root/.hermes/profiles/nexus/.env 2>/dev/null
export DEEPSEEK_API_KEY DEEPSEEK_BASE_URL
exec /root/NavMAX/.venv/bin/python /root/NavMAX/navmax/dark_triad/server.py 8484
