from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IROp:
    op: str
    dst: str | None = None
    src: str | int | None = None
    src2: str | int | None = None
    symbol: str | None = None
    source_address: int | None = None
    text: str = ""


@dataclass
class BasicBlock:
    name: str
    ops: list[IROp] = field(default_factory=list)


@dataclass
class Function:
    name: str
    blocks: list[BasicBlock] = field(default_factory=list)
