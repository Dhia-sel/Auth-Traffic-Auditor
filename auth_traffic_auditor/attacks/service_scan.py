from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

logger = logging.getLogger(__name__)
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    """Tente de lire une bannière applicative sur un port déjà ouvert.
    Certains services l'envoient sans rien demander (SSH, FTP), d'autres
    ne répondent qu'après une requête minimale (HTTP).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(256)
            except socket.timeout:
                banner = b""
            if not banner and port in (80, 8080, 443, 8443):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256)
                except (socket.timeout, OSError):
                    banner = b""
            return banner.decode(errors="ignore").strip() or None
    except OSError:
        return None


def _scan_port(host: str, port: int, timeout: float, grab_banners: bool) -> tuple[int, str | None] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (ConnectionRefusedError, OSError):
        return None  # port fermé/filtré, rien à signaler

    banner = _grab_banner(host, port, timeout) if grab_banners else None
    return port, banner


@register
class ServiceScanModule(AttackModule):
    name = "service_scan"
    iso_controls = ("A.12",)

    def run(
        self,
        target: str,
        ports: list[int] | None = None,
        timeout: float = 1.0,
        max_workers: int = 50,
        grab_banners: bool = True,
        **kwargs,
    ) -> AttackResult:
        """target = adresse IP ou nom d'hôte (sans schéma http://). Scanne
        `ports` (par défaut : liste de ports courants) en parallèle via
        un pool de threads — un scan TCP connect() classique, pas de
        paquets forgés, donc pas besoin de privilèges root.
        """
        if target.startswith(("http://", "https://")):
            raise ValueError(
                f"target doit être une IP ou un nom d'hôte sans schéma, reçu : {target!r}"
            )

        try:
            socket.gethostbyname(target)
        except socket.gaierror as exc:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Impossible de résoudre la cible '{target}' : {exc}",
                evidence={"target": target},
            )

        ports_to_scan = ports or DEFAULT_PORTS
        open_ports: dict[int, str | None] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_scan_port, target, port, timeout, grab_banners): port
                for port in ports_to_scan
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    port, banner = result
                    open_ports[port] = banner
                    logger.info("Port ouvert : %d (%s)", port, banner or "bannière inconnue")

        sorted_ports = dict(sorted(open_ports.items()))

        if sorted_ports:
            summary = (
                f"{len(sorted_ports)} port(s) ouvert(s) sur {len(ports_to_scan)} "
                f"testé(s) : {', '.join(str(p) for p in sorted_ports)}."
            )
        else:
            summary = f"Aucun port ouvert parmi les {len(ports_to_scan)} testés."

        return AttackResult(
            module_name=self.name,
            success=bool(sorted_ports),
            summary=summary,
            evidence={
                "target": target,
                "ports_ouverts": sorted_ports,
                "nb_ports_testes": len(ports_to_scan),
            },
        )