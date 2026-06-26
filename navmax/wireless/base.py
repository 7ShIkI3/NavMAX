"""BaseWirelessScanner — classe abstraite et dataclasses Pydantic pour le module wireless.

Définit les types partagés :
- HardwareCapability (monitor mode, injection, interface)
- WiFiNetwork (BSSID, ESSID, channel, signal, encryption)
- BLEDevice (adresse, nom, RSSI, UUIDs)
- Handshake (BSSID, station, fichier .cap/.22000, PMKID)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from pydantic import BaseModel, Field


class WirelessTech(str, Enum):
    """Technologies sans-fil supportées."""

    WIFI = "wifi"
    BLE = "ble"
    BOTH = "both"
    NONE = "none"


class HardwareCapability(BaseModel):
    """Capacités matérielles détectées.

    Attributes:
        available: True si au moins une interface sans-fil est disponible.
        interfaces: Liste des noms d'interfaces détectées (monitor ou non).
        monitor_mode: True si le monitor mode est disponible sur au moins une interface.
        packet_injection: True si l'injection de paquets est possible.
        ble_support: True si BLE est disponible (bleak peut se connecter).
        tech: Résumé (wifi / ble / both / none).
        error: Message d'erreur si la détection a échoué.
    """

    available: bool = False
    interfaces: list[str] = Field(default_factory=list)
    monitor_mode: bool = False
    packet_injection: bool = False
    ble_support: bool = False
    tech: WirelessTech = WirelessTech.NONE
    error: str | None = None


class WiFiNetwork(BaseModel):
    """Réseau WiFi découvert lors d'un scan.

    Attributes:
        bssid: Adresse MAC du point d'accès.
        essid: Nom du réseau (SSID).
        channel: Canal WiFi.
        signal: Intensité du signal en dBm.
        encryption: Type de chiffrement (WPA2, WPA3, WEP, OPEN…).
        privacy: Détails de confidentialité (CCMP, TKIP…).
        cipher: Algorithme de chiffrement.
        authentication: Type d'authentification (PSK, EAP…).
        beacon_interval: Intervalle des beacons en ms.
    """

    bssid: str
    essid: str
    channel: int = Field(default=0)
    signal: int = Field(default=0, description="RSSI en dBm")
    encryption: str = Field(default="")
    privacy: str = Field(default="")
    cipher: str = Field(default="")
    authentication: str = Field(default="")
    beacon_interval: int = Field(default=100)


class BLEDevice(BaseModel):
    """Périphérique BLE découvert.

    Attributes:
        address: Adresse MAC du périphérique.
        name: Nom broadcasté (peut être vide).
        rssi: Intensité du signal en dBm.
        uuid_services: Liste des UUIDs de services annoncés.
        manufacturer_data: Données manufacturier brutes (hex string).
        tx_power: Puissance d'émission si disponible.
    """

    address: str
    name: str = Field(default="")
    rssi: int = Field(default=0)
    uuid_services: list[str] = Field(default_factory=list)
    manufacturer_data: dict[int, str] = Field(
        default_factory=dict,
        description="Données manufacturier {company_id: hex_data}",
    )
    tx_power: int | None = Field(default=None)


class Handshake(BaseModel):
    """Handshake WiFi capturé (WPA/WPA2 PMKID ou 4-way).

    Attributes:
        bssid: Adresse MAC du point d'accès ciblé.
        station: Adresse MAC du client (peut être vide si PMKID).
        cap_file: Chemin vers le fichier .cap ou .pcapng.
        hash_file: Chemin vers le fichier .22000 (hashcat format).
        pmkid: PMKID extrait si disponible (hex string).
        complete: True si un handshake complet 4-way a été capturé.
        ap_name: ESSID du point d'accès (optionnel).
        encrypted: True si le handshake est chiffré WPA/WPA2.
    """

    bssid: str
    station: str = Field(default="")
    cap_file: str = Field(default="")
    hash_file: str = Field(default="")
    pmkid: str | None = Field(default=None)
    complete: bool = False
    ap_name: str | None = Field(default=None)
    encrypted: bool = True


class BaseWirelessScanner(ABC):
    """Classe abstraite pour tout scanner sans-fil.

    Définit le contrat commun : détection matérielle, scan,
    et opérations de base (connexion, déconnexion, injection).
    """

    @abstractmethod
    def check_hardware(self) -> HardwareCapability:
        """Détecte et retourne les capacités matérielles disponibles.

        Returns:
            HardwareCapability avec l'état de chaque technologie.
        """
        ...

    @abstractmethod
    def scan(self, timeout: int = 15) -> list:
        """Lance un scan des périphériques sans-fil environnants.

        Args:
            timeout: Durée du scan en secondes.

        Returns:
            Liste de découvertes (WiFiNetwork ou BLEDevice selon la sous-classe).
        """
        ...
