import requests


def is_login_success(resp: requests.Response) -> bool:
    if resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except ValueError:
        return True  # pas de JSON exploitable, on se fie au code 200
    if isinstance(data, dict) and "status" in data:
        return data["status"] == "ok"
    return True