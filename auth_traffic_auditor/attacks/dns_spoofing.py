from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

@register
class DnsSpoofingModule(AttackModule):
    name = "dns_spoofing"
    iso_controls = ("A.13",)

    def run(self, target: str, **kwargs) -> AttackResult:
        raise NotImplementedError("Module à implémenter — prochaine étape")