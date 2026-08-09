from ..core.plugin_base import AttackModule, AttackResult
from ..core.registry import register

@register
class PasswordSprayingModule(AttackModule):
    name = "password_spraying"
    iso_controls = ("A.9",)

    def run(self, target: str, **kwargs) -> AttackResult:
        raise NotImplementedError("Module à implémenter — prochaine étape")