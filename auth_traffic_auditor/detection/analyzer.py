from dataclasses import dataclass
from ..core.plugin_base import AttackResult

@dataclass
class Finding:
    severity: str
    recommendation: str

def analyze(result: AttackResult) -> Finding:
    if not result.success:
        return Finding(
            severity="Info",
            recommendation="Aucune faiblesse exploitée sur ce test — bonne pratique en place.",
        )
    return Finding(
        severity="Élevée",
        recommendation=(
            "Faiblesse confirmée : voir les contrôles ISO 27001 associés "
            "pour la remédiation attendue."
        ),
    )