from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json


@dataclass
class Evidence:
    binary: str
    entry: str
    verdict: str
    capabilities: list[dict] = field(default_factory=list)
    external_calls: list[dict] = field(default_factory=list)
    unsupported_instructions: list[dict] = field(default_factory=list)
    policy_violations: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)
