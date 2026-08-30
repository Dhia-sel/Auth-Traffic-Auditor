from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

@dataclass
class AttackResult:
    module_name: str
    success: bool
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AttackModule(ABC):
    name: str = "unnamed"
    iso_controls: tuple[str, ...] = ()
    requires_confirmation: bool = False

    @abstractmethod
    def run(self, target: str, **kwargs: Any) -> AttackResult:
        raise NotImplementedError