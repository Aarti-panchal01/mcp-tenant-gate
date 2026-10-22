"""Content scanners. Each returns a list of Finding; an empty list means clean."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # high | medium | low
    snippet: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "snippet": self.snippet[:120]}


def worst(findings: list[Finding]) -> str | None:
    order = {"high": 3, "medium": 2, "low": 1}
    if not findings:
        return None
    return max(findings, key=lambda f: order[f.severity]).severity
