from .plugin_base import AttackModule

_REGISTRY: dict[str, type[AttackModule]] = {}

def register(cls: type[AttackModule]) -> type[AttackModule]:
    _REGISTRY[cls.name] = cls
    return cls

def get_module(name: str) -> type[AttackModule]:
    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY)) or "aucun"
        raise KeyError(f"Module '{name}' introuvable. Disponibles : {available}")
    return _REGISTRY[name]

def available_modules() -> list[str]:
    return sorted(_REGISTRY)