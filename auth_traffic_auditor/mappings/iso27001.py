CONTROL_DESCRIPTIONS: dict[str, str] = {
    "A.9": "Contrôle d'accès — gestion des accès utilisateurs et authentification",
    "A.13": "Sécurité des communications — protection des informations en transit",
    "A.12": "Sécurité liée à l'exploitation — protection contre les malwares, journalisation",
    "A.8": "Gestion des actifs — inventaire et classification des actifs",
}

def describe_controls(refs: tuple[str, ...]) -> dict[str, str]:
    return {ref: CONTROL_DESCRIPTIONS.get(ref, "Description non renseignée") for ref in refs}