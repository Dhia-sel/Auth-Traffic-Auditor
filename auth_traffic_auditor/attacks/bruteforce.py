import requests
from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

DEFAULT_WORDLIST = [""]

@register
class BruteForceModule(AttackModule):
    name = "bruteforce"
    iso_controls = ("A.9",)

    def run(self, target: str, username: str = "admin", wordlist: list[str] | None = None, **kwargs) -> AttackResult:
        wordlist = wordlist or DEFAULT_WORDLIST
        attempts = 0
        for password in wordlist:
            attempts += 1
            resp = requests.post(
                f"{target}/login",
                json={"username": username, "password": password},
                timeout=3,
            )
            if resp.status_code == 200:
                return AttackResult(
                    module_name=self.name,
                    success=True,
                    summary=(
                        f"Mot de passe trouvé pour '{username}' en {attempts} tentative(s), sans blocage détecté."
                    ),
                    evidence={"username": username, "password": password, "attempts": attempts},
                )
        return AttackResult(
            module_name=self.name,
            success=False,
            summary=f"Aucun mot de passe trouvé après {attempts} tentatives.",
            evidence={"attempts": attempts},
        )