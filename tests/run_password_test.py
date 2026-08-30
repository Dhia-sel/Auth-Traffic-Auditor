from __future__ import annotations
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_traffic_auditor.attacks.arp_mitm import ArpMitmModule
from auth_traffic_auditor.attacks.bruteforce import BruteForceModule
from auth_traffic_auditor.attacks.dns_spoofing import DnsSpoofingModule
from auth_traffic_auditor.attacks.password_spraying import PasswordSprayingModule
from auth_traffic_auditor.attacks.service_scan import ServiceScanModule
from auth_traffic_auditor.attacks.sniffing import SniffingModule
from auth_traffic_auditor.core.plugin_base import AttackResult

LAB_URL = "http://127.0.0.1:5000"
LAB_SCRIPT = Path(__file__).resolve().parent.parent / "lab" / "dummy_login_server.py"

results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((name, condition, detail))
    status = "OK   " if condition else "ÉCHEC"
    suffix = f" — {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def test_bruteforce() -> None:
    m = BruteForceModule()

    result = m.run(LAB_URL, username="admin", wordlist=["mauvais1", "azerty", "mauvais2"])
    check(
        "bruteforce : trouve le bon mot de passe",
        result.success and result.evidence.get("password") == "azerty",
        result.summary,
    )

    result_fail = m.run(LAB_URL, username="admin", wordlist=["x1", "x2"])
    check(
        "bruteforce : échoue proprement si absent de la wordlist",
        result_fail.success is False,
        result_fail.summary,
    )


def test_password_spraying() -> None:
    m = PasswordSprayingModule()
    result = m.run(
        LAB_URL,
        usernames=["guest", "admin", "root"],
        passwords=["123456", "azerty"],
        delay=0,
        max_attempts_per_user=2,
    )
    compromised = [c["username"] for c in result.evidence.get("comptes_compromis", [])]
    check(
        "password_spraying : trouve le compte admin",
        result.success and "admin" in compromised,
        result.summary,
    )


def test_service_scan() -> None:
    m = ServiceScanModule()
    result = m.run("127.0.0.1", ports=[22, 80, 5000, 9999])
    check(
        "service_scan : détecte le port 5000 ouvert",
        5000 in result.evidence.get("ports_ouverts", {}),
        result.summary,
    )


def test_arp_mitm_smoke() -> None:
    check("arp_mitm : marqué comme dangereux (requires_confirmation)", ArpMitmModule.requires_confirmation is True)
    m = ArpMitmModule()
    # The module first checks for privileges; if not run as root it returns an
    # AttackResult indicating insufficient privileges. Accept either a
    # ValueError (if privilege check passed and gateway_ip missing) OR an
    # AttackResult with success=False describing privilege issue.
    try:
        res = m.run("10.0.0.5")  # gateway_ip manquant volontairement
        if isinstance(res, AttackResult):
            ok = res.success is False and ("privil" in res.summary.lower() or "root" in res.summary.lower())
            check("arp_mitm : valide gateway_ip obligatoire or privilege", ok, res.summary)
        else:
            check("arp_mitm : valide gateway_ip obligatoire", False, "retour inattendu")
    except ValueError:
        check("arp_mitm : valide gateway_ip obligatoire", True)


def test_dns_spoofing_smoke() -> None:
    check("dns_spoofing : marqué comme dangereux (requires_confirmation)", DnsSpoofingModule.requires_confirmation is True)
    m = DnsSpoofingModule()
    try:
        res = m.run("exemple.local")  # spoof_ip manquant volontairement
        if isinstance(res, AttackResult):
            ok = res.success is False and ("privil" in res.summary.lower() or "root" in res.summary.lower())
            check("dns_spoofing : valide spoof_ip obligatoire or privilege", ok, res.summary)
        else:
            check("dns_spoofing : valide spoof_ip obligatoire", False, "retour inattendu")
    except ValueError:
        check("dns_spoofing : valide spoof_ip obligatoire", True)


def test_sniffing_smoke() -> None:
    check("sniffing : marqué comme dangereux (requires_confirmation)", SniffingModule.requires_confirmation is True)


def main() -> int:
    print(f"Démarrage du serveur de lab ({LAB_SCRIPT})...")
    server = subprocess.Popen(
        [sys.executable, str(LAB_SCRIPT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)

    try:
        print("\n--- Modules HTTP (test complet contre le lab) ---")
        test_bruteforce()
        test_password_spraying()
        test_service_scan()

        print("\n--- Modules réseau bas niveau (test fumée — root+LAN requis pour un vrai test) ---")
        test_arp_mitm_smoke()
        test_dns_spoofing_smoke()
        test_sniffing_smoke()
    finally:
        server.terminate()
        server.wait(timeout=5)

    print("\n=== Résumé ===")
    for name, ok, _ in results:
        print(f"{'OK' if ok else 'FAIL'} {name}")

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"\n{len(failed)} test(s) échoué(s) sur {len(results)}.")
        return 1

    print(f"\nTous les tests ({len(results)}) sont passés.")
    return 0


if __name__ == "__main__":
    sys.exit(main())