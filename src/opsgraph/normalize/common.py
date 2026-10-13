from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NormalizeStats:
    processed: int = 0
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}
