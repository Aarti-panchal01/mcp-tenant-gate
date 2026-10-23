"""Tenant policy: who may call what, with which arguments.

The policy file (tenants.yaml) maps an API key (stored only as a SHA-256 hash)
to a tenant. Each tenant lists the upstreams and tools it may use, per-tool
argument constraints, rate limits, PII handling and an egress allowlist.

Tool patterns use the gateway's namespaced names, for example
``notes__read_note`` or ``notes__*``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .errors import GateBlocked

NAMESPACE_SEP = "__"

VALID_ARG_KINDS = {"url", "path", "resource", "identity"}
VALID_PII = {"email", "phone", "card", "pan", "aadhaar"}


class PolicyError(ValueError):
    """Raised when tenants.yaml is malformed. Fails closed at load time."""


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


@dataclass
class ArgRule:
    pattern: re.Pattern[str] | None = None
    kind: str | None = None  # url | path | resource | identity
    max_length: int | None = None


@dataclass
class ToolRule:
    pattern: str
    args: dict[str, ArgRule] = field(default_factory=dict)
    schema: dict[str, Any] | None = None
    resource_out: list[str] = field(default_factory=list)


@dataclass
class RateRule:
    capacity: float
    refill_per_sec: float


@dataclass
class Tenant:
    tenant_id: str
    key_hash: str
    upstreams: list[str]
    tools: list[ToolRule]
    rate: RateRule
    pii_categories: list[str]
    pii_mode: str  # redact | block
    injection_mode: str  # quarantine | wrap
    egress_allow: list[str]
    max_result_bytes: int
    path_root: str

    def tool_rule(self, namespaced: str) -> ToolRule | None:
        """Most specific matching rule wins (exact name beats a wildcard)."""
        exact = [t for t in self.tools if t.pattern == namespaced]
        if exact:
            return exact[0]
        wild = [t for t in self.tools if fnmatch.fnmatchcase(namespaced, t.pattern)]
        if not wild:
            return None
        return max(wild, key=lambda t: len(t.pattern))

    def allows(self, namespaced: str) -> bool:
        upstream = namespaced.split(NAMESPACE_SEP, 1)[0]
        return upstream in self.upstreams and self.tool_rule(namespaced) is not None


@dataclass
class UpstreamSpec:
    name: str
    command: str
    args: list[str]
    module: str | None  # for the in-process adapter


@dataclass
class Policy:
    tenants: dict[str, Tenant]
    upstreams: dict[str, UpstreamSpec]
    scanner_allow_hosts: list[str]

    def authenticate(self, api_key: str | None) -> Tenant:
        if not api_key:
            raise GateBlocked("auth", "missing API key")
        digest = hash_key(api_key)
        found = None
        # compare against every tenant so timing does not reveal position
        for tenant in self.tenants.values():
            if hmac.compare_digest(digest, tenant.key_hash):
                found = tenant
        if found is None:
            raise GateBlocked("auth", "unknown API key")
        return found

    def check_args(self, tenant: Tenant, namespaced: str, args: dict[str, Any]) -> ToolRule:
        rule = tenant.tool_rule(namespaced)
        if rule is None or not tenant.allows(namespaced):
            raise GateBlocked("policy", f"tool not available to tenant: {namespaced}")
        if rule.schema is not None:
            try:
                jsonschema.validate(args, rule.schema)
            except jsonschema.ValidationError as exc:
                raise GateBlocked("policy", f"argument schema: {exc.message}") from None
        for name, arg_rule in rule.args.items():
            if name not in args:
                continue
            value = args[name]
            if arg_rule.pattern is not None or arg_rule.max_length is not None:
                if not isinstance(value, str):
                    raise GateBlocked("policy", f"argument {name} must be a string")
                if arg_rule.max_length is not None and len(value) > arg_rule.max_length:
                    raise GateBlocked("policy", f"argument {name} too long")
                if arg_rule.pattern is not None and not arg_rule.pattern.fullmatch(value):
                    raise GateBlocked("policy", f"argument {name} fails pattern")
        return rule


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def _parse_tool(pattern: str, raw: Any) -> ToolRule:
    raw = raw or {}
    _require(isinstance(raw, dict), f"tool {pattern}: rule must be a mapping")
    _require(NAMESPACE_SEP in pattern, f"tool {pattern}: must be namespaced like upstream__tool")
    args: dict[str, ArgRule] = {}
    for arg_name, arg_raw in (raw.get("args") or {}).items():
        _require(isinstance(arg_raw, dict), f"tool {pattern} arg {arg_name}: must be a mapping")
        unknown = set(arg_raw) - {"pattern", "kind", "max_length"}
        _require(not unknown, f"tool {pattern} arg {arg_name}: unknown keys {sorted(unknown)}")
        kind = arg_raw.get("kind")
        _require(kind is None or kind in VALID_ARG_KINDS, f"tool {pattern} arg {arg_name}: bad kind {kind}")
        pat = arg_raw.get("pattern")
        try:
            compiled = re.compile(pat) if pat is not None else None
        except re.error as exc:
            raise PolicyError(f"tool {pattern} arg {arg_name}: bad regex: {exc}") from None
        args[arg_name] = ArgRule(pattern=compiled, kind=kind, max_length=arg_raw.get("max_length"))
    schema = raw.get("schema")
    if schema is not None:
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.SchemaError as exc:
            raise PolicyError(f"tool {pattern}: bad JSON schema: {exc.message}") from None
    resource_out = raw.get("resource_out") or []
    _require(isinstance(resource_out, list), f"tool {pattern}: resource_out must be a list")
    return ToolRule(pattern=pattern, args=args, schema=schema, resource_out=resource_out)


def parse_policy(data: dict[str, Any]) -> Policy:
    _require(isinstance(data, dict), "policy root must be a mapping")
    defaults = data.get("defaults") or {}
    ups_raw = data.get("upstreams") or {}
    _require(isinstance(ups_raw, dict) and ups_raw, "policy needs at least one upstream")
    upstreams: dict[str, UpstreamSpec] = {}
    for name, u in ups_raw.items():
        _require(re.fullmatch(r"[a-z][a-z0-9]{0,30}", name) is not None,
                 f"upstream name {name!r}: lowercase letters and digits only (no '_')")
        _require(isinstance(u, dict) and "command" in u, f"upstream {name}: needs a command")
        upstreams[name] = UpstreamSpec(name=name, command=u["command"], args=list(u.get("args") or []),
                                       module=u.get("module"))

    tenants_raw = data.get("tenants") or {}
    _require(isinstance(tenants_raw, dict) and tenants_raw, "policy needs at least one tenant")
    tenants: dict[str, Tenant] = {}
    seen_hashes: set[str] = set()
    for tid, t in tenants_raw.items():
        _require(isinstance(t, dict), f"tenant {tid}: must be a mapping")
        key_hash = t.get("api_key_sha256")
        _require(isinstance(key_hash, str) and re.fullmatch(r"[0-9a-f]{64}", key_hash) is not None,
                 f"tenant {tid}: api_key_sha256 must be 64 lowercase hex chars")
        _require(key_hash not in seen_hashes, f"tenant {tid}: duplicate API key")
        seen_hashes.add(key_hash)
        t_ups = list(t.get("upstreams") or [])
        for u in t_ups:
            _require(u in upstreams, f"tenant {tid}: unknown upstream {u}")
        tools = [_parse_tool(p, r) for p, r in (t.get("tools") or {}).items()]
        for rule in tools:
            _require(rule.pattern.split(NAMESPACE_SEP, 1)[0] in t_ups,
                     f"tenant {tid}: tool {rule.pattern} is on an upstream the tenant cannot use")
        rate_raw = t.get("rate_limit") or defaults.get("rate_limit") or {"capacity": 20, "refill_per_sec": 5}
        rate = RateRule(float(rate_raw["capacity"]), float(rate_raw["refill_per_sec"]))
        _require(rate.capacity > 0 and rate.refill_per_sec >= 0, f"tenant {tid}: bad rate limit")
        pii = list(t.get("pii", defaults.get("pii", [])) or [])
        for p in pii:
            _require(p in VALID_PII, f"tenant {tid}: unknown pii category {p}")
        pii_mode = t.get("pii_mode", defaults.get("pii_mode", "redact"))
        _require(pii_mode in {"redact", "block"}, f"tenant {tid}: pii_mode must be redact or block")
        inj = t.get("injection_mode", defaults.get("injection_mode", "quarantine"))
        _require(inj in {"quarantine", "wrap"}, f"tenant {tid}: injection_mode must be quarantine or wrap")
        tenants[tid] = Tenant(
            tenant_id=tid,
            key_hash=key_hash,
            upstreams=t_ups,
            tools=tools,
            rate=rate,
            pii_categories=pii,
            pii_mode=pii_mode,
            injection_mode=inj,
            egress_allow=list(t.get("egress_allow", defaults.get("egress_allow", [])) or []),
            max_result_bytes=int(t.get("max_result_bytes", defaults.get("max_result_bytes", 65536))),
            path_root=str(t.get("path_root", defaults.get("path_root", "data"))),
        )
    return Policy(tenants=tenants, upstreams=upstreams,
                  scanner_allow_hosts=list(defaults.get("description_url_allow", []) or []))


def load_policy(path: str | Path) -> Policy:
    with open(path, encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise PolicyError(f"YAML error: {exc}") from None
    return parse_policy(data)
