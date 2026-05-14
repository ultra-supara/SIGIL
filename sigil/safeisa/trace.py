from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TraceEvent:
    event: str
    blocked: bool
    symbol: str | None = None
    number: int | None = None
    capability: str | None = None
    pc: int | None = None
