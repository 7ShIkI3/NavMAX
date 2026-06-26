"""WiFiScanner — wrapper aircrack-ng suite + hcxtools.

Fonctionnalités :
- Activation du monitor mode (airmon-ng)
- Scan réseaux (airodump-ng --output-format csv)
- Déauthentification client (aireplay-ng)
- Capture de handshake (airodump-ng ciblé)
- Capture PMKID (hcxdumptool)
- Crack de handshake (hashcat -m 22000)
- Parsing CSV airodump

Chaque méthode lève une exception claire si l'outil requis est manquant.
"""

from __future__ import annotations

import csv
import io
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..core.logging import get_logger
from .base import (
    BaseWirelessScanner,
    Handshake,
    HardwareCapability,
    WiFiNetwork,
    WirelessTech,
)

logger = get_logger(__name__)

# ── Vérification des binaires requis ────────────────────────────

REQUIRED_WIFI_BINS = ["airmon-ng", "airodump-ng", "aireplay-ng", "airodump-ng-oui-update"]
OPTIONAL_WIFI_BINS = ["hcxdumptool", "hcxpcapngtool", "hashcat"]


def _check_binary(name: str) -> str | None:
    """Retourne le chemin absolu d'un binaire ou None s'il est introuvable.

    Args:
        name: Nom du binaire à chercher dans PATH.

    Returns:
        Chemin absolu ou None.
    """
    return shutil.which(name)


def _require_binary(name: str) -> str:
    """Vérifie qu'un binaire est disponible ou lève FileNotFoundError.

    Args:
        name: Nom du binaire.

    Returns:
        Chemin absolu du binaire.

    Raises:
        FileNotFoundError: Si le binaire est introuvable.
    """
    path = _check_binary(name)
    if path is None:
        msg = f"Binaire requis introuvable: '{name}'. Installez aircrack-ng ou l'outil concerné."
        raise FileNotFoundError(msg)
    return path


# ── Parsing CSV airodump ────────────────────────────────────────


def _parse_airodump_csv(csv_data: str) -> list[WiFiNetwork]:
    """Parse la sortie CSV d'airodump-ng en liste de WiFiNetwork.

    Le format airodump-ng --output-format csv produit 2 sections
    séparées par une ligne vide : "BSSID" (APs) puis "Station MAC"
    (clients). On ne parse que la première section.

    Les colonnes CSV d'airodump-ng ont des espaces dans les en-têtes.
    Cette fonction normalise les clés en supprimant les espaces superflus.

    Args:
        csv_data: Contenu brut du fichier CSV.

    Returns:
        Liste de WiFiNetwork découverts.
    """
    networks: list[WiFiNetwork] = []
    reader = csv.DictReader(io.StringIO(csv_data))

    for row in reader:
        # Normaliser les clés : supprimer les espaces de début/fin
        clean = {k.strip(): v.strip() if v else "" for k, v in row.items()}

        bssid = clean.get("BSSID", "")
        if not bssid or bssid == "BSSID" or bssid.startswith("Station MAC"):
            break  # fin de la section AP

        essid = clean.get("ESSID", "")

        try:
            channel = int(clean.get("channel", 0))
        except (ValueError, TypeError):
            channel = 0

        try:
            signal = int(clean.get("Power", -100))
        except (ValueError, TypeError):
            signal = -100

        network = WiFiNetwork(
            bssid=bssid,
            essid=essid,
            channel=channel,
            signal=signal,
            encryption=clean.get("Privacy", ""),
            cipher=clean.get("Cipher", ""),
            authentication=clean.get("Authentication", ""),
        )
        networks.append(network)

    return networks


# ── Classe principale ───────────────────────────────────────────


class WiFiScanner(BaseWirelessScanner):
    """Scanner WiFi utilisant aircrack-ng suite et hcxtools.

    Args:
        interface: Nom de l'interface WiFi (ex: wlan0). Si None,
                   le scanner tente de détecter la première interface
                   disponible.
    """

    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface
        self._monitor_interface: str | None = None

    # ── Détection matérielle ────────────────────────────────────

    def check_hardware(self) -> HardwareCapability:
        """Détecte les interfaces WiFi et les capacités monitor/injection.

        Utilise `iwconfig` ou `airmon-ng` pour lister les interfaces
        sans-fil. Vérifie la présence des binaires requis.

        Returns:
            HardwareCapability avec les capacités détectées.
        """
        interfaces: list[str] = []
        monitor = False
        inject = False

        # 1) Liste les interfaces via airmon-ng
        airmon_path = _check_binary("airmon-ng")
        if airmon_path:
            try:
                result = subprocess.run(
                    [airmon_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # airmon-ng affiche les interfaces dans sa sortie
                for line in result.stdout.splitlines():
                    # Format typique: "phy0  wlan0  ..."
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0].startswith("phy"):
                        iface = parts[1]
                        if iface not in interfaces:
                            interfaces.append(iface)
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("airmon-ng listing failed", error=str(exc))

        # Fallback: iwconfig
        if not interfaces:
            iw_path = _check_binary("iwconfig")
            if iw_path:
                try:
                    result = subprocess.run(
                        [iw_path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    for line in result.stdout.splitlines():
                        m = re.match(r"^(\S+)\s+", line)
                        if m:
                            iface = m.group(1)
                            if iface not in interfaces and iface != "lo":
                                interfaces.append(iface)
                except (subprocess.TimeoutExpired, OSError) as exc:
                    logger.warning("iwconfig listing failed", error=str(exc))

        # 2) Vérifier monitor mode sur chaque interface
        iw_path = _check_binary("iw")
        if iw_path:
            for iface in interfaces:
                try:
                    result = subprocess.run(
                        ["iw", iface, "info"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if "type monitor" in result.stdout:
                        monitor = True
                    # Injection implicite si monitor est dispo
                    if monitor:
                        inject = True
                except (subprocess.TimeoutExpired, OSError):
                    continue

        # 3) BLE support : bleak installé ?
        ble = False
        try:
            import bleak  # noqa: F401

            ble = True
        except ImportError:
            pass

        # 4) Assemblage du résultat
        tech = WirelessTech.NONE
        if interfaces and ble:
            tech = WirelessTech.BOTH
        elif interfaces:
            tech = WirelessTech.WIFI
        elif ble:
            tech = WirelessTech.BLE

        return HardwareCapability(
            available=bool(interfaces) or ble,
            interfaces=interfaces,
            monitor_mode=monitor,
            packet_injection=inject,
            ble_support=ble,
            tech=tech,
        )

    # ── Scan réseaux ────────────────────────────────────────────

    def scan(self, timeout: int = 15) -> list[WiFiNetwork]:
        """Lance un scan WiFi via airodump-ng.

        Args:
            timeout: Durée du scan en secondes (délai avant de lire
                     le fichier CSV).

        Returns:
            Liste de WiFiNetwork découverts.

        Raises:
            FileNotFoundError: Si airodump-ng est introuvable.
            RuntimeError: Si le scan échoue.
        """
        return self.scan_networks(timeout=timeout)

    def scan_networks(self, timeout: int = 15) -> list[WiFiNetwork]:
        """Lance un scan WiFi et parse la sortie CSV d'airodump-ng.

        Crée un fichier temporaire, lance airodump-ng en arrière-plan,
        attend `timeout` secondes, puis lit et parse le CSV.

        Args:
            timeout: Durée d'écoute en secondes.

        Returns:
            Liste de WiFiNetwork.

        Raises:
            FileNotFoundError: Si airodump-ng est introuvable.
            RuntimeError: Si le fichier CSV est vide ou illisible.
        """
        _require_binary("airodump-ng")
        interface = self._resolve_interface()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_prefix = Path(tmpdir) / "scan"
            cmd = [
                "airodump-ng",
                "--output-format",
                "csv",
                "-w",
                str(tmp_prefix),
                interface,
            ]

            logger.info("Starting WiFi scan", interface=interface, timeout=timeout)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(timeout)
                proc.terminate()
                proc.wait(timeout=5)
            except OSError as exc:
                msg = f"Échec du lancement d'airodump-ng: {exc}"
                raise RuntimeError(msg) from exc

            # Lecture du fichier CSV produit
            csv_path = tmp_prefix.with_suffix(".csv")
            if not csv_path.exists():
                # Parfois airodump produit un préfixe avec un tiret + num
                alt_csv = list(Path(tmpdir).glob("*.csv"))
                if not alt_csv:
                    msg = "Aucun fichier CSV produit par airodump-ng"
                    raise RuntimeError(msg)
                csv_path = alt_csv[0]

            raw = csv_path.read_text(encoding="utf-8", errors="replace")
            networks = _parse_airodump_csv(raw)
            logger.info("WiFi scan complete", networks_found=len(networks))
            return networks

    # ── Monitor mode ────────────────────────────────────────────

    def enable_monitor_mode(self, interface: str | None = None) -> bool:
        """Active le monitor mode sur une interface via airmon-ng.

        Args:
            interface: Nom de l'interface. Si None, utilise l'interface
                       configurée à l'init ou tente de détecter.

        Returns:
            True si le monitor mode a été activé avec succès.

        Raises:
            FileNotFoundError: Si airmon-ng est introuvable.
            RuntimeError: Si l'activation échoue.
        """
        airmon = _require_binary("airmon-ng")
        iface = interface or self._interface
        if iface is None:
            hw = self.check_hardware()
            if not hw.interfaces:
                msg = "Aucune interface sans-fil détectée"
                raise RuntimeError(msg)
            iface = hw.interfaces[0]

        logger.info("Enabling monitor mode", interface=iface)
        try:
            result = subprocess.run(
                [airmon, "start", iface],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                msg = f"airmon-ng start a échoué: {result.stderr.strip()}"
                raise RuntimeError(msg)

            # Essayer de déduire l'interface monitor (généralement
            # airmon-ng suffixe par "mon" ou crée une nouvelle interface)
            self._monitor_interface = iface
            # airmon-ng crée parfois wlan0mon ou renomme
            mon_pattern = re.compile(r"\(monitor mode enabled on (\S+)\)")
            m = mon_pattern.search(result.stdout)
            if m:
                self._monitor_interface = m.group(1)
            else:
                # Fallback: essayer iface + "mon"
                candidate = f"{iface}mon"
                iw_path = _check_binary("iw")
                if iw_path:
                    try:
                        subprocess.run(
                            ["iw", candidate, "info"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        self._monitor_interface = candidate
                    except OSError:
                        pass

            logger.info(
                "Monitor mode enabled",
                interface=iface,
                monitor_interface=self._monitor_interface,
            )
            return True

        except subprocess.TimeoutExpired as exc:
            msg = f"airmon-ng start a expiré (30s): {exc}"
            raise RuntimeError(msg) from exc

    def disable_monitor_mode(self, interface: str | None = None) -> bool:
        """Désactive le monitor mode via airmon-ng.

        Args:
            interface: Nom de l'interface monitor. Si None, utilise
                       l'interface monitor sauvegardée.

        Returns:
            True si la désactivation a réussi.

        Raises:
            FileNotFoundError: Si airmon-ng est introuvable.
            RuntimeError: Si la désactivation échoue.
        """
        airmon = _require_binary("airmon-ng")
        iface = interface or self._monitor_interface or self._interface
        if iface is None:
            msg = "Aucune interface à désactiver"
            raise RuntimeError(msg)

        logger.info("Disabling monitor mode", interface=iface)
        try:
            result = subprocess.run(
                [airmon, "stop", iface],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(
                    "airmon-ng stop returned non-zero",
                    stderr=result.stderr.strip(),
                )
            self._monitor_interface = None
            return True
        except subprocess.TimeoutExpired as exc:
            msg = f"airmon-ng stop a expiré (30s): {exc}"
            raise RuntimeError(msg) from exc

    # ── Déauthentification ──────────────────────────────────────

    def deauth_client(
        self,
        bssid: str,
        client: str,
        interface: str | None = None,
        count: int = 5,
    ) -> int:
        """Envoie des paquets de déauthentification via aireplay-ng.

        Args:
            bssid: BSSID du point d'accès cible.
            client: MAC du client à déauthentifier (ou "FF:FF:FF:FF:FF:FF"
                    pour broadcast).
            interface: Interface en monitor mode. Si None, utilise
                       l'interface monitor configurée.
            count: Nombre de paquets à envoyer (défaut: 5).

        Returns:
            Nombre de paquets envoyés (lecture depuis la sortie).

        Raises:
            FileNotFoundError: Si aireplay-ng est introuvable.
            RuntimeError: Si l'injection échoue.
        """
        _require_binary("aireplay-ng")
        iface = interface or self._monitor_interface or self._interface
        if iface is None:
            msg = "Aucune interface monitor configurée. Appelez enable_monitor_mode() d'abord."
            raise RuntimeError(msg)

        logger.info(
            "Sending deauth packets",
            bssid=bssid,
            client=client,
            count=count,
            interface=iface,
        )

        try:
            result = subprocess.run(
                [
                    "aireplay-ng",
                    "--deauth",
                    str(count),
                    "-a",
                    bssid,
                    "-c",
                    client,
                    iface,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                msg = f"aireplay-ng a échoué: {result.stderr.strip()}"
                raise RuntimeError(msg)

            # Essayer d'extraire le nombre de paquets depuis la sortie
            sent_match = re.search(r"(\d+)\s+packets", result.stdout or result.stderr)
            sent = int(sent_match.group(1)) if sent_match else count
            logger.info("Deauth packets sent", sent=sent)
            return sent

        except subprocess.TimeoutExpired as exc:
            msg = f"aireplay-ng a expiré (30s): {exc}"
            raise RuntimeError(msg) from exc

    # ── Capture de handshake ────────────────────────────────────

    def capture_handshake(
        self,
        bssid: str,
        channel: int,
        output_file: str | Path,
        timeout: int = 30,
    ) -> Handshake:
        """Capture un handshake WPA/WPA2 4-way via airodump-ng ciblé.

        Lance airodump-ng sur le canal et BSSID spécifiés, puis
        convertit le fichier .cap en format hashcat .22000 via
        hcxpcapngtool (optionnel).

        Args:
            bssid: BSSID du point d'accès cible.
            channel: Canal WiFi.
            output_file: Chemin du fichier .cap/.pcapng de sortie.
            timeout: Durée de capture en secondes.

        Returns:
            Handshake avec les chemins et métadonnées.

        Raises:
            FileNotFoundError: Si airodump-ng est introuvable.
            RuntimeError: Si la capture échoue.
        """
        _require_binary("airodump-ng")
        interface = self._resolve_interface()
        output_path = Path(output_file)
        output_stem = output_path.with_suffix("").with_suffix("").stem

        logger.info(
            "Starting handshake capture",
            bssid=bssid,
            channel=channel,
            output=output_file,
            timeout=timeout,
        )

        try:
            proc = subprocess.Popen(
                [
                    "airodump-ng",
                    "--bssid",
                    bssid,
                    "--channel",
                    str(channel),
                    "-w",
                    str(output_stem),
                    "--output-format",
                    "pcap",
                    interface,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(timeout)
            proc.terminate()
            proc.wait(timeout=5)
        except OSError as exc:
            msg = f"Échec du lancement d'airodump-ng ciblé: {exc}"
            raise RuntimeError(msg) from exc

        # Chercher le fichier .cap produit
        cap_candidates = list(Path(output_stem).parent.glob(f"{output_stem}*"))
        cap_file = None
        for c in cap_candidates:
            if c.suffix in (".cap", ".pcap", ".pcapng"):
                cap_file = c
                break
        if cap_file is None:
            msg = f"Aucun fichier de capture trouvé pour {output_stem}"
            raise RuntimeError(msg)

        # Conversion .22000 via hcxpcapngtool si dispo
        hash_file: str = ""
        hcxpcap_path = _check_binary("hcxpcapngtool")
        if hcxpcap_path:
            hc_output = cap_file.with_suffix(".22000")
            try:
                subprocess.run(
                    [hcxpcap_path, "-o", str(hc_output), str(cap_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if hc_output.exists():
                    hash_file = str(hc_output)
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("hcxpcapngtool conversion failed", error=str(exc))

        handshake = Handshake(
            bssid=bssid,
            cap_file=str(cap_file),
            hash_file=hash_file,
            complete=True,
        )
        logger.info("Handshake capture complete", cap_file=str(cap_file))
        return handshake

    # ── Capture PMKID ───────────────────────────────────────────

    def capture_pmkid(
        self,
        bssid: str,
        output_file: str | Path,
        timeout: int = 60,
    ) -> Handshake:
        """Capture le PMKID d'un point d'accès via hcxdumptool.

        Nécessite hcxdumptool installé et une interface en monitor mode.

        Args:
            bssid: BSSID du point d'accès cible.
            output_file: Fichier de sortie (format .pcapng ou .cap).
            timeout: Durée de capture en secondes.

        Returns:
            Handshake avec le PMKID si extrait.

        Raises:
            FileNotFoundError: Si hcxdumptool est introuvable.
            RuntimeError: Si la capture échoue.
        """
        hcxdump = _require_binary("hcxdumptool")
        interface = self._monitor_interface or self._interface
        if interface is None:
            msg = "Aucune interface monitor configurée."
            raise RuntimeError(msg)

        output_path = Path(output_file)

        logger.info(
            "Starting PMKID capture",
            bssid=bssid,
            output=str(output_path),
            timeout=timeout,
        )

        try:
            proc = subprocess.Popen(
                [
                    hcxdump,
                    "-i",
                    interface,
                    "--filterlist_ap",
                    "-",  # stdin pour la liste des APs?
                    "-o",
                    str(output_path),
                    "--enable_status",
                    "1",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Envoyer BSSID via stdin pour filterlist_ap
            proc.stdin.write(f"{bssid}\n".encode())
            proc.stdin.flush()
            proc.stdin.close()

            time.sleep(timeout)
            proc.terminate()
            proc.wait(timeout=5)
        except OSError as exc:
            msg = f"Échec du lancement d'hcxdumptool: {exc}"
            raise RuntimeError(msg) from exc

        # Conversion .22000 si hcxpcapngtool dispo
        hash_file: str = ""
        pmkid_val: str | None = None
        hcxpcap_path = _check_binary("hcxpcapngtool")
        if hcxpcap_path and output_path.exists():
            hc_output = output_path.with_suffix(".22000")
            try:
                subprocess.run(
                    [hcxpcap_path, "-o", str(hc_output), str(output_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if hc_output.exists():
                    hash_file = str(hc_output)
                    # Lire le PMKID depuis le .22000
                    content = hc_output.read_text(errors="replace")
                    parts = content.strip().split("*")
                    if len(parts) >= 4:
                        pmkid_val = parts[2]
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("hcxpcapngtool conversion failed", error=str(exc))

        handshake = Handshake(
            bssid=bssid,
            cap_file=str(output_path),
            hash_file=hash_file,
            pmkid=pmkid_val,
            complete=True,
        )
        logger.info("PMKID capture complete", pmkid=pmkid_val is not None)
        return handshake

    # ── Crack de handshake ──────────────────────────────────────

    def crack_handshake(
        self,
        handshake_file: str | Path,
        wordlist: str | Path,
    ) -> str | None:
        """Tente de casser un handshake via hashcat -m 22000.

        Args:
            handshake_file: Fichier .22000 ou .cap contenant le handshake.
            wordlist: Chemin vers la wordlist (txt).

        Returns:
            La clé trouvée (str) ou None si aucun mot de passe n'a matché.

        Raises:
            FileNotFoundError: Si hashcat est introuvable.
            RuntimeError: Si le cracking échoue.
        """
        hashcat = _require_binary("hashcat")
        hf_path = Path(handshake_file)
        wl_path = Path(wordlist)

        if not hf_path.exists():
            msg = f"Fichier handshake introuvable: {hf_path}"
            raise FileNotFoundError(msg)
        if not wl_path.exists():
            msg = f"Wordlist introuvable: {wl_path}"
            raise FileNotFoundError(msg)

        logger.info(
            "Starting handshake crack",
            handshake=str(hf_path),
            wordlist=str(wl_path),
        )

        try:
            result = subprocess.run(
                [
                    hashcat,
                    "-m",
                    "22000",
                    str(hf_path),
                    str(wl_path),
                    "--show",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Format: hash:password
                lines = result.stdout.strip().splitlines()
                for line in lines:
                    if ":" in line:
                        password = line.split(":", 1)[1]
                        logger.info("Password cracked successfully")
                        return password

            # Si --show ne retourne rien, essayer en mode cracking
            result = subprocess.run(
                [
                    hashcat,
                    "-m",
                    "22000",
                    str(hf_path),
                    str(wl_path),
                    "--potfile-disable",
                    "-O",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                for line in lines:
                    if ":" in line:
                        password = line.split(":", 1)[1]
                        logger.info("Password cracked successfully")
                        return password

            logger.info("No password found in wordlist")
            return None

        except subprocess.TimeoutExpired:
            logger.warning("hashcat cracking timed out (300s)")
            return None
        except OSError as exc:
            msg = f"Échec du lancement de hashcat: {exc}"
            raise RuntimeError(msg) from exc

    # ── Méthodes internes ───────────────────────────────────────

    def _resolve_interface(self) -> str:
        """Retourne l'interface à utiliser pour un scan.

        Priorité :
        1. Interface monitor configurée
        2. Interface constructeur
        3. Auto-détection

        Returns:
            Nom de l'interface.

        Raises:
            RuntimeError: Si aucune interface n'est disponible.
        """
        iface = self._monitor_interface or self._interface
        if iface:
            return iface
        hw = self.check_hardware()
        if hw.interfaces:
            return hw.interfaces[0]
        msg = "Aucune interface sans-fil détectée"
        raise RuntimeError(msg)
