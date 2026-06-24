"""
Module Scanner — reconnaissance réseau (Nmap-like).

Fonctionnalités :
- TCP Connect Scan (sans privilèges admin)
- UDP Scan (nécessite admin)
- Détection de services (banner grabbing)
- Fingerprinting OS (TTL, flags TCP)
"""

from .engine import run_scan, run_scan_background, parse_ports
from .tcp import tcp_connect_scan
from .fingerprint import detect_os, detect_service

__all__ = ["run_scan", "run_scan_background", "parse_ports", "tcp_connect_scan", "detect_os", "detect_service"]
