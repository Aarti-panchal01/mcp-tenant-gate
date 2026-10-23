"""Playground engine for the website. Every verdict comes from the real gateway.

The serverless function keeps no state between requests. Instead the browser
sends the list of operations it has already run (``history``) plus a session
seed, and this module rebuilds the session by replaying those operations
through a fresh ``Gateway`` before running the new one. Replayed operations go
through every gateway check again, so a client cannot fake state (for example
claim to own another tenant's note): the only way to own a note is to create
it through the gateway.

Differences from the repo's own runs, all on purpose:

- Note ids in the in-process notes server come from ``uuid.uuid4``. Here they
  come from a random generator seeded with the session seed, so a replay
  creates the same ids. The gateway code is untouched.
- The rate limiter runs on a fake clock that moves one second between
  operations, so replaying a long history does not trip the bucket. The
  "flood" operation fires many calls at one instant to show the real limit.
- One extra in-process upstream, ``paste``, returns whatever text it is given.
  It exists so pasted text can travel the real result path (size cap,
  cross-tenant filter, PII, injection scan). It is not shown in tool lists.

Nothing here touches the file system or the network on behalf of a user. The
notes server's ``read_file`` and ``fetch_url`` are dictionary lookups on fake
data, and they only run if the gateway's argument guard lets the call through.
"""

from __future__ import annotations

import json
import random
import sys
import time
import uuid as _uuid
from pathlib import Path
from typing import Any

CORE = Path(__file__).resolve().parent / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

import anyio  # noqa: E402

import upstreams.notes_server as notes_mod  # noqa: E402
from mcp_tenant_gate.audit import AuditLog  # noqa: E402
from mcp_tenant_gate.core import Gateway  # noqa: E402
from mcp_tenant_gate.policy import ToolRule, UpstreamSpec, load_policy  # noqa: E402
from mcp_tenant_gate.ratelimit import FakeClock, RateLimiter  # noqa: E402
from mcp_tenant_gate.scanners import classifier, injection, pii  # noqa: E402
from mcp_tenant_gate.upstream import InProcessUpstream  # noqa: E402
from upstreams.common import obj_schema, text_result  # noqa: E402
from upstreams.evil_server import EvilApp  # noqa: E402
from upstreams.notes_server import NotesApp  # noqa: E402

POLICY_PATH = CORE / "tenants.yaml"
KEYS = {"acme": "acme-demo-key-7f3a", "globex": "globex-demo-key-91c2", "unknown": "guessed-key-0000"}
PASTE_TOOL = "paste__result"

MAX_HISTORY = 150
MAX_ARGS_JSON = 8000
MAX_TEXT = 6000
MAX_FLOOD = 60


class BadRequest(ValueError):
    pass


class PasteApp:
    """Playground-only upstream: returns the text it is given, as a tool result."""

    def list_tools(self) -> list[dict[str, Any]]:
        return [{"name": "result", "description": "Return the given text as a tool result.",
                 "inputSchema": obj_schema({"text": {"type": "string"}})}]

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return text_result(str(args.get("text", "")))


class _SeededUuid:
    """Stands in for the ``uuid`` module inside the notes server, so ids replay."""

    def __init__(self, seed: str):
        self._rng = random.Random(seed)

    def uuid4(self) -> _uuid.UUID:
        return _uuid.UUID(int=self._rng.getrandbits(128), version=4)


def _build(seed: str) -> tuple[Gateway, FakeClock, NotesApp, EvilApp]:
    policy = load_policy(POLICY_PATH)
    policy.upstreams["paste"] = UpstreamSpec("paste", "python", [], None)
    for t in policy.tenants.values():
        t.upstreams.append("paste")
        t.tools.append(ToolRule(pattern=PASTE_TOOL))
    notes_mod.uuid = _SeededUuid(seed)  # type: ignore[attr-defined]
    notes, evil = NotesApp(), EvilApp()
    ups = {"notes": InProcessUpstream("notes", notes), "evil": InProcessUpstream("evil", evil),
           "paste": InProcessUpstream("paste", PasteApp())}
    clock = FakeClock(1_000_000.0)
    gate = Gateway(policy, ups, audit=AuditLog(clock=lambda: clock.now), limiter=RateLimiter(clock))
    return gate, clock, notes, evil


# ---------------------------------------------------------------- validation

def _tenant(op: dict[str, Any]) -> str:
    t = op.get("tenant")
    if t not in KEYS:
        raise BadRequest("tenant must be acme, globex or unknown")
    return t


def _args(op: dict[str, Any]) -> dict[str, Any]:
    args = op.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise BadRequest("args must be a JSON object")
    if len(json.dumps(args)) > MAX_ARGS_JSON:
        raise BadRequest(f"args are larger than {MAX_ARGS_JSON} bytes")
    return args


def _tool(op: dict[str, Any]) -> str:
    tool = op.get("tool")
    if not isinstance(tool, str) or not (1 <= len(tool) <= 120):
        raise BadRequest("tool must be a string of 1 to 120 characters")
    return tool


def _validate_seed(seed: Any) -> str:
    if not isinstance(seed, str) or not (4 <= len(seed) <= 64) or not seed.isalnum():
        raise BadRequest("seed must be 4 to 64 letters or digits")
    return seed


# ---------------------------------------------------------------- views

def _catalog_view(gate: Gateway) -> dict[str, Any]:
    tools = []
    for full, e in sorted(gate.catalog.items()):
        if e.upstream == "paste":
            continue
        tools.append({"name": full, "upstream": e.upstream, "status": e.status, "reasons": e.reasons,
                      "description": str(e.tool.get("description", ""))})
    rejected = []
    for line in gate.audit.lines():
        rec = json.loads(line)
        if rec["event"] == "tool_rejected":
            item = {"name": f"{rec['upstream']}__{rec['tool']}", "reason": rec["reason"]}
            if item not in rejected:
                rejected.append(item)
    return {"tools": tools, "rejected": rejected}


def _visible(gate: Gateway, tenant: str) -> list[dict[str, Any]]:
    t = gate.policy.tenants.get(tenant)
    if t is None:
        return []
    return [gate._exposed(t, full, e) for full, e in sorted(gate.catalog.items())
            if e.status == "approved" and t.allows(full) and e.upstream != "paste"]


def _audit_view(gate: Gateway, since: int) -> dict[str, Any]:
    lines = gate.audit.lines()
    v = gate.audit.verify()
    recs = [json.loads(line) for line in lines]
    for r in recs:
        if r.get("tool") == PASTE_TOOL:
            r["tool"] = "paste__result (playground)"
    return {"total": len(recs), "chain_ok": v.ok, "head": gate.audit.head(), "new": recs[since:][-30:],
            "tail": recs[-12:]}


def _outcome(out) -> dict[str, Any]:
    texts = [c.get("text", "") for c in out.result.get("content", [])]
    return {"blocked": out.blocked, "layer": out.layer, "reason": out.reason, "actions": out.actions,
            "text": "\n".join(texts)[:4000], "is_error": bool(out.result.get("isError"))}


# ---------------------------------------------------------------- ops

async def _run_op(gate: Gateway, clock: FakeClock, op: dict[str, Any], live: bool) -> dict[str, Any] | None:
    if not isinstance(op, dict):
        raise BadRequest("each op must be an object")
    kind = op.get("t")
    tenant = _tenant(op)
    key = KEYS[tenant]
    clock.advance(1.0)

    if kind == "list":
        try:
            tools = await gate.list_tools(key)
            return {"kind": "list", "blocked": False, "visible": [t["name"] for t in tools if t["name"] != PASTE_TOOL]}
        except Exception as exc:  # GateBlocked for an unknown key
            return {"kind": "list", "blocked": True, "layer": getattr(exc, "layer", "auth"),
                    "reason": getattr(exc, "reason", str(exc)), "visible": []}

    if kind == "call":
        tool = _tool(op)
        if tool == PASTE_TOOL and not live:
            raise BadRequest("paste ops are not replayed")
        out = await gate.call_tool(key, tool, _args(op))
        return {"kind": "call", "tool": tool, **_outcome(out)}

    if not live:
        raise BadRequest(f"op {kind!r} cannot be in history")

    if kind == "flood":
        tool = _tool(op)
        n = op.get("n", 30)
        if not isinstance(n, int) or not (1 <= n <= MAX_FLOOD):
            raise BadRequest(f"n must be 1 to {MAX_FLOOD}")
        args = _args(op)
        results = []
        for _ in range(n):  # all at the same fake instant
            out = await gate.call_tool(key, tool, dict(args))
            results.append({"blocked": out.blocked, "layer": out.layer, "reason": out.reason})
        allowed = sum(not r["blocked"] for r in results)
        t = gate.policy.tenants.get(tenant)
        clock.advance(60.0)  # let the bucket refill so the session keeps working
        return {"kind": "flood", "tool": tool, "n": n, "allowed": allowed,
                "capacity": t.rate.capacity if t else None, "refill_per_sec": t.rate.refill_per_sec if t else None,
                "results": results}

    if kind == "scan":
        text = op.get("text")
        if not isinstance(text, str) or not text:
            raise BadRequest("text must be a non-empty string")
        if len(text) > MAX_TEXT:
            raise BadRequest(f"text is longer than {MAX_TEXT} characters")
        out = await gate.call_tool(key, PASTE_TOOL, {"text": text})
        t = gate.policy.tenants.get(tenant)
        detail: dict[str, Any] = {}
        if t is not None:
            # the same scanner functions the gateway just ran, called directly so the
            # page can show each finding and the classifier score
            started = time.perf_counter()
            rules_only = injection.scan_result(text, gate.policy.scanner_allow_hosts, use_classifier=False)
            with_clf = injection.scan_result(text, gate.policy.scanner_allow_hosts, use_classifier=True)
            scan_ms = (time.perf_counter() - started) * 1000
            model = classifier.load_model()
            detail = {
                "mode": t.injection_mode,
                "pii_mode": t.pii_mode,
                "pii_categories": t.pii_categories,
                "pii_hits": sorted({h.category for h in pii.find_pii(text, t.pii_categories)}),
                "rules_findings": [f.as_dict() for f in rules_only],
                "findings": [f.as_dict() for f in with_clf],
                "classifier_score": round(classifier.score(text), 4),
                "t_high": model["t_high"] if model else None,
                "t_low": model["t_low"] if model else None,
                "scan_ms": round(scan_ms, 3),
            }
        return {"kind": "scan", **_outcome(out), "detail": detail}

    raise BadRequest("op t must be list, call, flood or scan")


async def _session(seed: str, history: list[Any], op: dict[str, Any]) -> dict[str, Any]:
    gate, clock, notes, _evil = _build(seed)
    replayed = 0
    for h in history:
        await _run_op(gate, clock, h, live=False)
        replayed += 1
    since = len(gate.audit.lines())
    started = time.perf_counter()
    result = await _run_op(gate, clock, op, live=True)
    ms = (time.perf_counter() - started) * 1000
    tenant = op.get("tenant")
    if not gate.catalog:
        await gate.refresh_catalog()
    return {
        "result": result,
        "ms": round(ms, 3),
        "replayed": replayed,
        "catalog": _catalog_view(gate),
        "visible": {name: [t["name"] for t in _visible(gate, name)] for name in ("acme", "globex")},
        "schemas": {t["name"]: {"description": t.get("description", ""), "inputSchema": t.get("inputSchema")}
                    for t in _visible(gate, tenant if tenant in ("acme", "globex") else "acme")},
        "tenants": {tid: {"upstreams": [u for u in t.upstreams if u != "paste"], "pii": t.pii_categories,
                          "pii_mode": t.pii_mode, "injection_mode": t.injection_mode,
                          "egress_allow": t.egress_allow, "path_root": t.path_root,
                          "rate": {"capacity": t.rate.capacity, "refill_per_sec": t.rate.refill_per_sec},
                          "max_result_bytes": t.max_result_bytes}
                    for tid, t in gate.policy.tenants.items()},
        "upstream_notes": [{"note_id": n["note_id"], "owner": n["owner"], "title": n["title"]}
                           for n in notes.notes.values()],
        "ledger": dict(gate.ledger._owner),
        "audit": _audit_view(gate, since),
    }


def handle(body: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")
    seed = _validate_seed(body.get("seed"))
    history = body.get("history") or []
    if not isinstance(history, list) or len(history) > MAX_HISTORY:
        raise BadRequest(f"history must be a list of at most {MAX_HISTORY} ops")
    op = body.get("op")
    if not isinstance(op, dict):
        raise BadRequest("op must be an object")
    try:
        return anyio.run(_session, seed, history, op)
    finally:
        notes_mod.uuid = _uuid  # put the real module back for anything else in this process


def run_suite() -> dict[str, Any]:
    """Run the repo's attack suite in-process, exactly as `python -m attacks.suite` does,
    without writing the report file."""
    from attacks import suite
    started = time.perf_counter()
    s = anyio.run(suite.run, "inprocess", False)
    s["seconds"] = round(time.perf_counter() - started, 2)
    return s
