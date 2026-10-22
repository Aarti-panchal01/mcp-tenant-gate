"""Errors shared by every layer."""

from __future__ import annotations


class GateBlocked(Exception):
    """A request or result was stopped. ``layer`` names the layer that caught it."""

    def __init__(self, layer: str, reason: str, detail: dict | None = None):
        super().__init__(f"[{layer}] {reason}")
        self.layer = layer
        self.reason = reason
        self.detail = detail or {}
