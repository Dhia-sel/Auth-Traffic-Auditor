
from __future__ import annotations

from typing import Callable

import requests
SuccessCheck = Callable[[requests.Response], bool]


def is_login_success(resp: requests.Response) -> bool:
    """Heuristique par défaut : valide une réponse de login au-delà du
    seul code HTTP 200, pour éviter les faux positifs si l'appli cible
    renvoie 200 avec un corps d'échec (ex: {"status": "invalid
    credentials"} avec code 200 quand même).

    Ne convient pas à toutes les cibles (ex: succès signalé par un champ
    JSON différent, une redirection, ou un cookie de session). Dans ce
    cas, ne modifiez pas cette fonction : passez un `success_check`
    personnalisé au paramètre `run(..., success_check=...)` du module
    (bruteforce, password_spraying) — cette fonction reste le défaut.
    """
    if resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except ValueError:
        return True 
    if isinstance(data, dict) and "status" in data:
        return data["status"] == "ok"
    return True