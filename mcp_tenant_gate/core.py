"""The gateway core: every request and every result passes through here.

This module knows nothing about transports. It takes plain dicts in the MCP
shapes (``tools/list`` entries and ``tools/call`` results) and talks to
upstreams through the small ``Upstream`` protocol in ``upstream.py``. The
stdio MCP server in ``gateway.py`` and the in-process attack suite both
drive this same class, so the suite tests the code that ships.

Order of checks on ``tools/call`` (cheapest and most certain first):

1. auth          API key -> tenant (unknown keys never see anything)
2. ratelimit     token bucket per tenant
3. policy        tool allowed for this tenant, and approved in the catalog
4. policy        tenant argument rules (JSON schema, regex, max length)
5. argguard      url / path arguments (SSRF, traversal)
6. isolation     identity arguments forced, resource ids must be owned
7. schema        upstream input schema (no extra or smuggled arguments)
8. upstream call (with a timeout)
9. result: size cap -> non-text content -> cross-tenant filter ->
   resource harvest -> PII -> prompt injection (patterns, then optional judge)

Every decision, allowed or blocked, is appended to the hash-chained audit
log with digests of arguments and results (not the raw data).
"""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from typing import Any

import anyio
import jsonschema

from . import argguard
from .audit import AuditLog, digest
from .errors import GateBlocked
from .isolation import (ResourceLedger, apply_identity_and_resources, bare_name_problem, filter_cross_tenant,
                        harvest_resources, namespaced, split_name)
from .judge import Judge
from .policy import Policy, Tenant
from .ratelimit import RateLimiter
from .scanners import Finding
from .scanners import injection as injection_scanner
from .scanners import pii as pii_scanner
from .scanners.tool_poisoning import PinStore, is_poisoned, scan_tool
from .upstream import Upstream


@dataclass
class CatalogEntry:
    upstream: str
    tool: dict[str, Any]
    status: str  # approved | quarantined
    reasons: list[str] = field(default_factory=list)


@dataclass
class CallOutcome:
    result: dict[str, Any]
    blocked: bool
    layer: str | None = None
    reason: str = ""
    actions: list[str] = field(default_factory=list)  # non-blocking changes, e.g. "pii_redacted"


def _text_of(result: dict[str, Any]) -> list[str]:
    return [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]


def _error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


class Gateway:
    def __init__(self, policy: Policy, upstreams: dict[str, Upstream], audit: AuditLog | None = None,
                 pins: PinStore | None = None, limiter: RateLimiter | None = None, judge: Judge | None = None,
                 upstream_timeout: float = 30.0):
        self.policy = policy
        self.upstreams = upstreams
        self.audit = audit or AuditLog()
        self.pins = pins or PinStore()
        self.limiter = limiter or RateLimiter()
        self.judge = judge
        self.upstream_timeout = upstream_timeout
        self.ledger = ResourceLedger()
        self.catalog: dict[str, CatalogEntry] = {}

    # ------------------------------------------------------------------ catalog

    async def refresh_catalog(self) -> dict[str, CatalogEntry]:
        """Ask every upstream for its tools, scan them and check their pins.

        Called on every client ``tools/list``, so a definition that changes
        after approval (a rug pull) is caught the next time anyone lists.
        """
        raw: dict[str, list[dict[str, Any]]] = {}
        for name, up in self.upstreams.items():
            try:
                with anyio.fail_after(self.upstream_timeout):
                    raw[name] = await up.list_tools()
            except Exception as exc:  # one broken upstream must not hide the others
                self.audit.append("upstream_error", upstream=name, op="tools/list", error=type(exc).__name__)
                raw[name] = []

        bare_owner: dict[str, set[str]] = {}
        for up_name, tools in raw.items():
            for t in tools:
                bare_owner.setdefault(str(t.get("name")), set()).add(up_name)

        catalog: dict[str, CatalogEntry] = {}
        for up_name, tools in raw.items():
            for tool in tools:
                bare = str(tool.get("name"))
                problem = bare_name_problem(bare)
                if problem:
                    self.audit.append("tool_rejected", upstream=up_name, tool=bare[:80], reason=problem)
                    continue
                findings = scan_tool(tool, self.policy.scanner_allow_hosts)
                findings += self._shadowing_findings(up_name, tool, bare_owner, findings)
                reasons = sorted({f.rule for f in findings if f.severity in ("high", "medium")})
                status = "approved"
                if is_poisoned(findings):
                    status = "quarantined"
                pin_status, new_hash, pinned = self.pins.check(up_name, tool)
                if pin_status == "changed":
                    status = "quarantined"
                    reasons.append("definition_changed_since_pinned")
                    self.audit.append("rug_pull", upstream=up_name, tool=bare, pinned=pinned, seen=new_hash)
                full = namespaced(up_name, bare)
                catalog[full] = CatalogEntry(up_name, tool, status, reasons)
                if status == "quarantined":
                    self.audit.append("tool_quarantined", tool=full, reasons=reasons,
                                      findings=[f.as_dict() for f in findings][:10])
        self.catalog = catalog
        return catalog

    @staticmethod
    def _shadowing_findings(up_name: str, tool: dict[str, Any], bare_owner: dict[str, set[str]],
                            findings: list[Finding]) -> list[Finding]:
        """A description that names a tool living on a *different* upstream and
        tells the model to prefer this one is trying to hijack that tool's traffic."""
        desc = str(tool.get("description") or "")
        redirect = any(f.rule == "tool_redirect" for f in findings)
        out = []
        for other_bare, owners in bare_owner.items():
            foreign_owners = owners - {up_name}
            if not foreign_owners or len(other_bare) < 4:
                continue
            if re.search(r"(?<![\w-])" + re.escape(other_bare) + r"(?![\w-])", desc):
                sev = "high" if redirect else "medium"
                out.append(Finding("tool_shadowing", sev,
                                   f"description refers to {other_bare} on {', '.join(sorted(foreign_owners))}"))
        return out

    def _exposed(self, tenant: Tenant, full: str, entry: CatalogEntry) -> dict[str, Any]:
        """The tool as this tenant sees it: namespaced, with identity arguments
        removed from the schema (the gateway fills them, the model never should)."""
        tool = copy.deepcopy(entry.tool)
        tool["name"] = full
        rule = tenant.tool_rule(full)
        hidden = [n for n, a in (rule.args.items() if rule else []) if a.kind == "identity"]
        schema = tool.get("inputSchema") or {"type": "object"}
        props = schema.get("properties") or {}
        for n in hidden:
            props.pop(n, None)
        if "required" in schema:
            schema["required"] = [r for r in schema["required"] if r not in hidden]
        tool["inputSchema"] = schema
        return tool

    # ------------------------------------------------------------------ tools/list

    async def list_tools(self, api_key: str | None) -> list[dict[str, Any]]:
        try:
            tenant = self.policy.authenticate(api_key)
        except GateBlocked as exc:
            self.audit.append("blocked", op="tools/list", layer=exc.layer, reason=exc.reason)
            raise
        await self.refresh_catalog()
        visible = [self._exposed(tenant, full, e) for full, e in sorted(self.catalog.items())
                   if e.status == "approved" and tenant.allows(full)]
        self.audit.append("list", tenant=tenant.tenant_id, tools=[t["name"] for t in visible])
        return visible

    # ------------------------------------------------------------------ tools/call

    async def call_tool(self, api_key: str | None, name: str, args: dict[str, Any] | None) -> CallOutcome:
        started = time.perf_counter()
        tenant_id = None
        args = dict(args or {})
        try:
            tenant = self.policy.authenticate(api_key)
            tenant_id = tenant.tenant_id
            outcome = await self._call(tenant, name, args)
        except GateBlocked as exc:
            self.audit.append("blocked", op="tools/call", tenant=tenant_id, tool=str(name)[:120], layer=exc.layer,
                              reason=exc.reason, args_digest=digest(args),
                              ms=round((time.perf_counter() - started) * 1000, 3))
            return CallOutcome(_error_result(f"[mcp-tenant-gate] blocked by {exc.layer}: {exc.reason}"),
                               blocked=True, layer=exc.layer, reason=exc.reason)
        self.audit.append("call", tenant=tenant_id, tool=name, args_digest=digest(args),
                          result_digest=digest(outcome.result), actions=outcome.actions,
                          ms=round((time.perf_counter() - started) * 1000, 3))
        return outcome

    async def _call(self, tenant: Tenant, name: str, args: dict[str, Any]) -> CallOutcome:
        rule_lim = tenant.rate
        if not self.limiter.allow(tenant.tenant_id, rule_lim.capacity, rule_lim.refill_per_sec):
            raise GateBlocked("ratelimit", "rate limit exceeded")

        if not isinstance(name, str):
            raise GateBlocked("policy", "tool name must be a string")
        up_name, bare = split_name(name)
        if not self.catalog:
            await self.refresh_catalog()
        entry = self.catalog.get(name)
        # same message for "does not exist", "not yours" and "quarantined": no probing
        if entry is None or not tenant.allows(name) or up_name not in self.upstreams:
            raise GateBlocked("policy", f"tool not available: {name}")
        if entry.status != "approved":
            raise GateBlocked("tool_poisoning", f"tool is quarantined: {', '.join(entry.reasons)}")

        rule = self.policy.check_args(tenant, name, args)

        for arg_name, arg_rule in rule.args.items():
            if arg_name not in args:
                continue
            if arg_rule.kind == "url":
                argguard.check_url(args[arg_name], tenant.egress_allow, arg_name)
            elif arg_rule.kind == "path":
                # forward exactly the string that was checked
                args[arg_name] = argguard.check_path(args[arg_name], tenant.path_root, arg_name)

        args = apply_identity_and_resources(tenant, rule, args, self.ledger)

        schema = entry.tool.get("inputSchema")
        if schema:
            try:
                jsonschema.validate(args, schema)
            except jsonschema.ValidationError as exc:
                raise GateBlocked("schema", f"arguments do not match the tool schema: {exc.message}") from None
            except jsonschema.SchemaError:
                raise GateBlocked("schema", "upstream published an invalid input schema") from None

        try:
            with anyio.fail_after(self.upstream_timeout):
                result = await self.upstreams[up_name].call_tool(bare, args)
        except TimeoutError:
            raise GateBlocked("upstream", "upstream timed out") from None
        except GateBlocked:
            raise
        except Exception as exc:
            raise GateBlocked("upstream", f"upstream error: {type(exc).__name__}") from None

        return await self._filter_result(tenant, rule, up_name, result)

    async def _filter_result(self, tenant: Tenant, rule, up_name: str, result: dict[str, Any]) -> CallOutcome:
        actions: list[str] = []
        content = list(result.get("content") or [])

        # 1. size cap, measured on everything the upstream sent
        size = sum(len(str(c.get("text", "")).encode("utf-8")) + len(str(c.get("data", ""))) for c in content)
        if size > tenant.max_result_bytes:
            raise GateBlocked("size_cap", f"result is {size} bytes, cap is {tenant.max_result_bytes}")

        # 2. scanners only read text, so anything else is dropped rather than passed unread
        texts = [c for c in content if c.get("type") == "text"]
        if len(texts) != len(content):
            actions.append(f"dropped_non_text:{len(content) - len(texts)}")

        out_texts: list[str] = []
        for c in texts:
            text = str(c.get("text", ""))

            # 3. another tenant's resource ids: drop those list items, or block
            text, dropped = filter_cross_tenant(tenant, text, self.ledger)
            if dropped:
                actions.append(f"cross_tenant_filtered:{dropped}")
                self.audit.append("cross_tenant_filtered", tenant=tenant.tenant_id, upstream=up_name, ids=dropped)
            out_texts.append(text)

        # 4. remember ids this call created or returned, so later calls can be checked
        harvest_resources(tenant, rule, out_texts, self.ledger)

        final: list[str] = []
        for text in out_texts:
            # 5. PII
            if tenant.pii_categories:
                hits = pii_scanner.find_pii(text, tenant.pii_categories)
                if hits and tenant.pii_mode == "block":
                    raise GateBlocked("pii", f"result contains PII: {sorted({h.category for h in hits})}")
                if hits:
                    text, counts = pii_scanner.redact(text, tenant.pii_categories)
                    actions.append("pii_redacted:" + ",".join(f"{k}={v}" for k, v in sorted(counts.items())))
                    self.audit.append("pii_redacted", tenant=tenant.tenant_id, upstream=up_name, counts=counts)

            # 6. prompt injection, patterns first
            decision = injection_scanner.decide(text, tenant.injection_mode, up_name, self.policy.scanner_allow_hosts)
            if decision.action == "quarantine":
                self.audit.append("quarantine", tenant=tenant.tenant_id, upstream=up_name,
                                  original_digest=digest(text), findings=[f.as_dict() for f in decision.findings])
                raise GateBlocked("injection", "result withheld: " +
                                  ", ".join(sorted({f.rule for f in decision.findings})))
            if decision.action == "wrap":
                actions.append("injection_wrapped")
            text = decision.text

            # 7. optional LLM judge: can only add a block, never remove one
            if self.judge is not None and decision.action == "pass":
                verdict = await anyio.to_thread.run_sync(self.judge.classify, text)
                if verdict.label == "injection":
                    raise GateBlocked("judge", f"LLM judge ({verdict.provider}) flagged the result")
                if verdict.label == "unknown":
                    actions.append("judge_unavailable")
            final.append(text)

        return CallOutcome({"content": [{"type": "text", "text": t} for t in final],
                            "isError": bool(result.get("isError", False))}, blocked=False, actions=actions)

    async def close(self) -> None:
        # reverse start order: each stdio upstream owns an anyio task group, and
        # task groups must be exited last-in, first-out or anyio raises
        for up in reversed(list(self.upstreams.values())):
            try:
                await up.close()
            except Exception:
                pass
