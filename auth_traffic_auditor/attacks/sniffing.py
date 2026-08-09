from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

@register
class SniffingModule(AttackModule):
    name = "sniffing"
    iso_controls = ("A.13",)

    def run(self, target: str, **kwargs) -> AttackResult:
        raise NotImplementedError("Module à implémenter — prochaine étape")