"""Append-only JSONL audit log with a SHA-256 hash chain.

Each record carries ``prev`` (the previous record's hash) and ``hash`` (the
hash of this record's canonical JSON without the ``hash`` field). Editing,
deleting, reordering or inserting a line breaks the chain, and ``verify``
reports the first bad line. This detects tampering after the fact; it does
not prevent someone with write access from rewriting the whole file and
re-hashing it. Anchoring the latest hash somewhere else (a ticket, a second
log, a signed checkpoint) closes that gap; see ``head()``.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def digest(value: Any) -> str:
    """Hash of arbitrary JSON data, so the log can prove what was sent without storing it."""
    return hashlib.sha256(_canonical({"v": value})).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    bad_line: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | Path | None = None, clock=time.time):
        self.path = Path(path) if path else None
        self._clock = clock
        self._lock = threading.Lock()
        self._memory: list[str] = []
        self._seq = 0
        self._prev = GENESIS
        if self.path and self.path.exists():
            result = verify_lines(self.path.read_text(encoding="utf-8").splitlines())
            if not result.ok:
                raise ValueError(f"refusing to append to a broken audit log: line {result.bad_line}: {result.reason}")
            lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                self._seq = last["seq"]
                self._prev = last["hash"]

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            record = {"seq": self._seq, "ts": round(self._clock(), 6), "event": event, "prev": self._prev, **fields}
            record["hash"] = record_hash(record)
            line = json.dumps(record, sort_keys=True, ensure_ascii=True)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # "a" mode: the OS appends at end of file for every write
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                self._memory.append(line)
            self._prev = record["hash"]
            return record

    def head(self) -> str:
        return self._prev

    def lines(self) -> list[str]:
        if self.path:
            return self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        return list(self._memory)

    def verify(self) -> VerifyResult:
        return verify_lines(self.lines())


def verify_lines(lines: list[str], expected_head: str | None = None) -> VerifyResult:
    prev = GENESIS
    count = 0
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(False, count, i, "not valid JSON")
        if rec.get("seq") != count + 1:
            return VerifyResult(False, count, i, f"sequence gap: expected {count + 1}, got {rec.get('seq')}")
        if rec.get("prev") != prev:
            return VerifyResult(False, count, i, "prev hash does not match previous record")
        if rec.get("hash") != record_hash(rec):
            return VerifyResult(False, count, i, "record hash mismatch (content edited)")
        prev = rec["hash"]
        count += 1
    if expected_head is not None and prev != expected_head:
        return VerifyResult(False, count, None, "chain head does not match anchored head (truncated or rewritten)")
    return VerifyResult(True, count)


def verify_file(path: str | Path, expected_head: str | None = None) -> VerifyResult:
    return verify_lines(Path(path).read_text(encoding="utf-8").splitlines(), expected_head)
