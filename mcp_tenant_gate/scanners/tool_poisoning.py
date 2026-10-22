"""Tool poisoning checks on tools/list results, plus description hash pinning.

A poisoned tool hides instructions for the model in places the user rarely
reads: the description, parameter descriptions, defaults or enum values.
We scan all string fields of the tool definition, not only ``description``.

Pinning: the first time the gateway sees a tool it records a SHA-256 of the
name, description and input schema. If a later tools/list returns a
different hash (a "rug pull": approve a harmless tool, then swap the text),
the tool is quarantined until an operator re-approves it.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from . import Finding
from .text_rules import base64_blobs, imperatives, invisible_chars, urls

MAX_DESCRIPTION_CHARS = 2000


def _strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_strings(k, f"{path}.key") if isinstance(k, str) and len(k) > 30 else [])
            out.extend(_strings(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_strings(v, f"{path}[{i}]"))
    return out


def scan_tool(tool: dict[str, Any], allow_hosts: list[str] | None = None) -> list[Finding]:
    allow_hosts = allow_hosts or []
    fields = [("description", tool.get("description") or ""), ("name", tool.get("name") or "")]
    fields += _strings(tool.get("inputSchema") or {}, "inputSchema")
    findings: list[Finding] = []
    for where, text in fields:
        if not text:
            continue
        for f in invisible_chars(text) + imperatives(text) + urls(text, allow_hosts) + base64_blobs(text):
            findings.append(Finding(f.rule, f.severity, f"{where}: {f.snippet}"))
    desc = tool.get("description") or ""
    if len(desc) > MAX_DESCRIPTION_CHARS:
        findings.append(Finding("oversized_description", "medium", f"{len(desc)} chars"))
    return findings


def is_poisoned(findings: list[Finding]) -> bool:
    highs = sum(f.severity == "high" for f in findings)
    mediums = sum(f.severity == "medium" for f in findings)
    return highs >= 1 or mediums >= 2


def fingerprint(tool: dict[str, Any]) -> str:
    body = {"name": tool.get("name"), "description": tool.get("description") or "",
            "inputSchema": tool.get("inputSchema") or {}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


class PinStore:
    """Trust on first use for tool definitions, keyed by upstream and tool name."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._pins: dict[str, str] = {}
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self._pins = json.loads(self.path.read_text(encoding="utf-8"))

    def check(self, upstream: str, tool: dict[str, Any]) -> tuple[str, str, str | None]:
        """Returns (status, new_hash, pinned_hash). status is new, same or changed."""
        key = f"{upstream}/{tool.get('name')}"
        fp = fingerprint(tool)
        with self._lock:
            pinned = self._pins.get(key)
            if pinned is None:
                self._pins[key] = fp
                self._save()
                return "new", fp, None
            return ("same" if pinned == fp else "changed"), fp, pinned

    def approve(self, upstream: str, tool: dict[str, Any]) -> None:
        with self._lock:
            self._pins[f"{upstream}/{tool.get('name')}"] = fingerprint(tool)
            self._save()

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # write then rename, so a crash mid-write never leaves half a pin file
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._pins, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
