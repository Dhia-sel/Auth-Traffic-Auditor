from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

@register
class ServiceScanModule(AttackModule):
    name = "service_scan"
    iso_controls = ("A.12",)

    def run(self, target: str, **kwargs) -> AttackResult:
        raise NotImplementedError("Module à implémenter — prochaine étape")