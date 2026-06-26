"""BLEScanner — wrapper BLE utilisant bleak.

Fonctionnalités :
- Scan des périphériques BLE avec bleak
- Connexion à un périphérique
- Lecture/écriture de caractéristiques
- Énumération des services
- Fallback élégant si bleak n'est pas installé

Chaque méthode lève une exception claire si bleak est manquant.
"""

from __future__ import annotations

from typing import Any

from ..core.logging import get_logger
from .base import BLEDevice, BaseWirelessScanner, HardwareCapability, WirelessTech

logger = get_logger(__name__)

# ── Vérification de bleak ───────────────────────────────────────

_bleak_available: bool | None = None


def _is_bleak_available() -> bool:
    """Vérifie si le module bleak est installé et importable.

    Returns:
        True si bleak peut être importé.
    """
    global _bleak_available
    if _bleak_available is not None:
        return _bleak_available
    try:
        import bleak  # noqa: F401

        _bleak_available = True
    except ImportError:
        _bleak_available = False
    return _bleak_available


def _require_bleak() -> None:
    """Vérifie que bleak est installé ou lève une exception.

    Raises:
        ImportError: Si bleak n'est pas installé.
    """
    if not _is_bleak_available():
        msg = (
            "Le module 'bleak' est requis pour utiliser BLEScanner. "
            "Installez-le avec : pip install bleak"
        )
        raise ImportError(msg)


# ── Classe principale ───────────────────────────────────────────


class BLEScanner(BaseWirelessScanner):
    """Scanner BLE utilisant bleak.

    Args:
        adapter: Nom de l'adaptateur BLE (Windows: "hci0" ou "bluetooth").
                 Laisser None pour l'adaptateur par défaut.
    """

    def __init__(self, adapter: str | None = None) -> None:
        self._adapter = adapter

    # ── Détection matérielle ────────────────────────────────────

    def check_hardware(self) -> HardwareCapability:
        """Détecte si BLE est disponible.

        Vérifie :
        1. Présence de bleak installé
        2. Présence d'un adaptateur BLE via bleak

        Returns:
            HardwareCapability avec ble_support.
        """
        if not _is_bleak_available():
            return HardwareCapability(
                available=False,
                ble_support=False,
                tech=WirelessTech.NONE,
                error="bleak n'est pas installé",
            )

        try:
            import bleak  # noqa: F811

            # bleak.BleakScanner.discover() peut échouer silencieusement
            interfaces: list[str] = []
            # Essayer de lister les adaptateurs (bleak >= 0.22)
            try:
                adapters = bleak.BleakScanner.discover(timeout=0.01)
                # Si on arrive ici, le scan a fonctionné
                interfaces.append(self._adapter or "default")
            except Exception as exc:
                logger.debug("BLE scan for detection failed", error=str(exc))
                # bleak peut être installé mais aucun adaptateur dispo
                return HardwareCapability(
                    available=False,
                    ble_support=True,
                    interfaces=[],
                    tech=WirelessTech.BLE,
                    error=f"Adaptateur BLE non détecté: {exc}",
                )

            return HardwareCapability(
                available=True,
                ble_support=True,
                interfaces=interfaces,
                tech=WirelessTech.BLE,
            )

        except ImportError:
            return HardwareCapability(
                available=False,
                ble_support=False,
                tech=WirelessTech.NONE,
                error="bleak n'est pas installé",
            )

    # ── Scan ────────────────────────────────────────────────────

    async def scan(self, timeout: int = 10) -> list[BLEDevice]:
        """Lance un scan BLE (version asynchrone).

        Args:
            timeout: Durée du scan en secondes.

        Returns:
            Liste de BLEDevice découverts.

        Raises:
            ImportError: Si bleak n'est pas installé.
        """
        return await self.scan_devices(timeout=timeout)

    async def scan_devices(self, timeout: int = 10) -> list[BLEDevice]:
        """Lance un scan BLE asynchrone via BleakScanner.

        Args:
            timeout: Durée du scan en secondes.

        Returns:
            Liste de BLEDevice.

        Raises:
            ImportError: Si bleak n'est pas installé.
        """
        _require_bleak()
        from bleak import BleakScanner

        devices: list[BLEDevice] = []
        logger.info("Starting BLE scan", timeout=timeout)

        try:
            scanner = BleakScanner(adapter=self._adapter)
            discovered = await scanner.discover(timeout=timeout, return_adv=True)

            for address, adv_data in discovered.items():
                # adv_data est un tuple (BLEDevice, AdvertisementData)
                if isinstance(adv_data, tuple):
                    bleak_device, adv = adv_data
                else:
                    bleak_device = adv_data
                    adv = None

                name = bleak_device.name or ""
                rssi = bleak_device.rssi if bleak_device.rssi is not None else 0

                uuids: list[str] = []
                mfg_data: dict[int, str] = {}

                if adv is not None:
                    if hasattr(adv, "service_uuids") and adv.service_uuids:
                        uuids = list(adv.service_uuids) if adv.service_uuids else []
                    if hasattr(adv, "manufacturer_data") and adv.manufacturer_data:
                        mfg_data = {
                            str(k): v.hex()
                            if isinstance(v, (bytes, bytearray))
                            else str(v)
                            for k, v in adv.manufacturer_data.items()
                        }

                device = BLEDevice(
                    address=address,
                    name=name,
                    rssi=rssi,
                    uuid_services=uuids,
                    manufacturer_data=mfg_data,
                )
                devices.append(device)

            logger.info("BLE scan complete", devices_found=len(devices))
            return devices

        except Exception as exc:
            logger.error("BLE scan failed", error=str(exc))
            raise

    # ── Connexion ───────────────────────────────────────────────

    async def connect_device(self, address: str) -> Any:
        """Établit une connexion BLE vers un périphérique.

        Args:
            address: Adresse MAC du périphérique.

        Returns:
            Instance de BleakClient connectée.

        Raises:
            ImportError: Si bleak n'est pas installé.
            ConnectionError: Si la connexion échoue.
        """
        _require_bleak()
        from bleak import BleakClient

        logger.info("Connecting to BLE device", address=address)

        try:
            client = BleakClient(address, adapter=self._adapter)
            await client.connect()
            logger.info("Connected to BLE device", address=address)
            return client
        except Exception as exc:
            msg = f"Échec de connexion BLE à {address}: {exc}"
            raise ConnectionError(msg) from exc

    async def disconnect_device(self, client: Any) -> bool:
        """Ferme une connexion BLE.

        Args:
            client: Instance BleakClient connectée.

        Returns:
            True si la déconnexion a réussi.
        """
        try:
            await client.disconnect()
            logger.info("Disconnected from BLE device")
            return True
        except Exception as exc:
            logger.warning("BLE disconnect failed", error=str(exc))
            return False

    # ── Caractéristiques ────────────────────────────────────────

    async def read_characteristic(self, address: str, uuid: str) -> bytes:
        """Lit une caractéristique BLE.

        Args:
            address: Adresse MAC du périphérique.
            uuid: UUID de la caractéristique à lire.

        Returns:
            Données brutes lues (bytes).

        Raises:
            ImportError: Si bleak n'est pas installé.
            ConnectionError: Si la lecture échoue.
        """
        _require_bleak()
        from bleak import BleakClient

        logger.info("Reading BLE characteristic", address=address, uuid=uuid)

        try:
            async with BleakClient(address, adapter=self._adapter) as client:
                data = await client.read_gatt_char(uuid)
                logger.info(
                    "Read BLE characteristic",
                    uuid=uuid,
                    length=len(data),
                )
                return data
        except Exception as exc:
            msg = f"Échec de lecture caractéristique {uuid} sur {address}: {exc}"
            raise ConnectionError(msg) from exc

    async def write_characteristic(
        self,
        address: str,
        uuid: str,
        data: bytes,
        response: bool = False,
    ) -> None:
        """Écrit sur une caractéristique BLE.

        Args:
            address: Adresse MAC du périphérique.
            uuid: UUID de la caractéristique.
            data: Données à écrire (bytes).
            response: True pour attendre une confirmation (write with response).

        Raises:
            ImportError: Si bleak n'est pas installé.
            ConnectionError: Si l'écriture échoue.
        """
        _require_bleak()
        from bleak import BleakClient

        logger.info(
            "Writing BLE characteristic",
            address=address,
            uuid=uuid,
            length=len(data),
            response=response,
        )

        try:
            async with BleakClient(address, adapter=self._adapter) as client:
                await client.write_gatt_char(uuid, data, response=response)
                logger.info("Wrote BLE characteristic", uuid=uuid)
        except Exception as exc:
            msg = f"Échec d'écriture caractéristique {uuid} sur {address}: {exc}"
            raise ConnectionError(msg) from exc

    # ── Services ────────────────────────────────────────────────

    async def list_services(self, address: str) -> list[str]:
        """Liste les services BLE d'un périphérique.

        Args:
            address: Adresse MAC du périphérique.

        Returns:
            Liste des UUIDs de services sous forme de chaînes.

        Raises:
            ImportError: Si bleak n'est pas installé.
            ConnectionError: Si l'énumération échoue.
        """
        _require_bleak()
        from bleak import BleakClient

        logger.info("Listing BLE services", address=address)
        services_desc: list[str] = []

        try:
            async with BleakClient(address, adapter=self._adapter) as client:
                for service in client.services:
                    # service.uuid, service.description, service.handle
                    desc = f"UUID={service.uuid}"
                    if service.description:
                        desc += f" ({service.description})"
                    # Caractéristiques du service
                    chars = []
                    for char in service.characteristics:
                        props = ",".join(char.properties) if char.properties else ""
                        chars.append(f"  Char: {char.uuid} [{props}]")
                    if chars:
                        desc += "\n" + "\n".join(chars)
                    services_desc.append(desc)

            logger.info(
                "Listed BLE services",
                address=address,
                count=len(services_desc),
            )
            return services_desc

        except Exception as exc:
            msg = f"Échec d'énumération des services sur {address}: {exc}"
            raise ConnectionError(msg) from exc
