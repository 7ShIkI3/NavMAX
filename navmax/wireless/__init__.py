"""Module Wireless — wrappers WiFi et BLE.

Fonctionnalités :
- Détection de capacités matérielles (monitor mode, injection, BLE)
- Scan WiFi (airodump-ng) avec parsing CSV
- Déauthentification client (aireplay-ng)
- Capture de handshake WPA/WPA2 (airodump-ng ciblé)
- Capture PMKID (hcxdumptool)
- Crack de handshake (hashcat -m 22000)
- Scan BLE (bleak)
- Connexion, lecture/écriture caractéristiques BLE
"""

from .base import (
    BLEDevice,
    BaseWirelessScanner,
    Handshake,
    HardwareCapability,
    WiFiNetwork,
    WirelessTech,
)
from .ble_scanner import BLEScanner
from .wifi_scanner import WiFiScanner

__all__ = [
    "BLEDevice",
    "BLEScanner",
    "BaseWirelessScanner",
    "Handshake",
    "HardwareCapability",
    "WiFiNetwork",
    "WiFiScanner",
    "WirelessTech",
]
