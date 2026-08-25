import requests
from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register
from ..core.http_utils import is_login_success

DEFAULT_WORDLIST: list[str] = []


@register
class BruteForceModule(AttackModule):
    name = "bruteforce"
    iso_controls = ("A.9",)

    def run(self, target: str, username: str = "admin", wordlist: list[str] | None = None, **kwargs) -> AttackResult:
        if not target.startswith(("http://", "https://")):
            raise ValueError(f"target doit être une URL http(s), reçu : {target!r}")

        wordlist = list(wordlist) if wordlist is not None else list(DEFAULT_WORDLIST)
        if not wordlist:
            return AttackResult(
                module_name=self.name,
                success=False,
                summary="Aucun mot de passe fourni (wordlist vide).",
                evidence={"attempts": 0},
            )

        attempts = 0
        session = requests.Session()
        try:
            for password in wordlist:
                attempts += 1
                try:
                    resp = session.post(
                        f"{target.rstrip('/')}/login",
                        json={"username": username, "password": password},
                        timeout=3,
                    )
                except requests.exceptions.RequestException:
                    # réseau / timeout : on continue avec la liste
                    continue

                if is_login_success(resp):
                    return AttackResult(
                        module_name=self.name,
                        success=True,
                        summary=(
                            f"Mot de passe trouvé pour '{username}' en {attempts} tentative(s), sans blocage détecté."
                        ),
                        evidence={"username": username, "password": password, "attempts": attempts},
                    )

        finally:
            session.close()

        return AttackResult(
            module_name=self.name,
            success=False,
            summary=f"Aucun mot de passe trouvé après {attempts} tentative(s).",
            evidence={"attempts": attempts},
        )