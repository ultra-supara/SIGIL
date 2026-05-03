from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Instruction:
    op: str
    a: str | int | None = None
    b: str | int | None = None
    c: str | int | None = None


@dataclass
class Program:
    instructions: list[Instruction]
