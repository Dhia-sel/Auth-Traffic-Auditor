from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

@register
class ArpMitmModule(AttackModule):
    name = "arp_mitm"
    iso_controls = ("A.13",)

    def run(self, target: str, **kwargs) -> AttackResult:
        raise NotImplementedError("Module à implémenter — prochaine étape")