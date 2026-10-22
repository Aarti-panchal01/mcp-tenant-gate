"""Per-tenant isolation.

Three jobs:

1. Namespacing. Every upstream tool is exposed as ``<upstream>__<tool>`` and a
   tenant only ever sees the names its policy allows. A tool that is not
   allowed is reported as "not available", never as "forbidden", so a tenant
   cannot probe which tools other tenants have.
2. Identity arguments. Arguments marked ``kind: identity`` (for example
   ``owner``) are filled in by the gateway with the caller's tenant id. A
   caller that supplies a different value is blocked as a spoof.
3. Resource ownership. Resource ids that come back from a tenant's calls
   (``resource_out``) are recorded in a ledger. Arguments marked
   ``kind: resource`` must name an id the caller owns, and results that
   mention another tenant's ids are filtered or blocked.

The upstreams behind the gateway can stay naive single-tenant servers.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any

from .errors import GateBlocked
from .policy import NAMESPACE_SEP, Tenant, ToolRule


def namespaced(upstream: str, tool: str) -> str:
    return f"{upstream}{NAMESPACE_SEP}{tool}"


def split_name(name: str) -> tuple[str, str]:
    if NAMESPACE_SEP not in name:
        raise GateBlocked("policy", f"tool not available: {name}")
    up, tool = name.split(NAMESPACE_SEP, 1)
    return up, tool


def bare_name_problem(tool_name: str) -> str | None:
    """Reasons an upstream's own tool name is unsafe to namespace."""
    if NAMESPACE_SEP in tool_name:
        return "tool name contains the namespace separator (could impersonate another upstream)"
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", tool_name):
        return "tool name has characters outside [A-Za-z0-9_.-] or is too long"
    return None


def _id_pattern(rid: str) -> re.Pattern[str]:
    # whole-token match, so "note-1" does not match inside "note-12"
    return re.compile(r"(?<![\w-])" + re.escape(rid) + r"(?![\w-])")


class ResourceLedger:
    def __init__(self) -> None:
        self._owner: dict[str, str] = {}
        self._lock = threading.Lock()

    def owner_of(self, resource_id: str) -> str | None:
        return self._owner.get(resource_id)

    def record(self, tenant_id: str, resource_id: str) -> None:
        with self._lock:
            current = self._owner.get(resource_id)
            if current is not None and current != tenant_id:
                raise GateBlocked("isolation", "upstream returned a resource id owned by another tenant",
                                  {"resource": resource_id})
            self._owner[resource_id] = tenant_id

    def foreign_ids(self, tenant_id: str, text: str) -> list[str]:
        with self._lock:
            items = list(self._owner.items())
        return [rid for rid, owner in items
                if owner != tenant_id and rid in text and _id_pattern(rid).search(text)]


def apply_identity_and_resources(tenant: Tenant, rule: ToolRule, args: dict[str, Any],
                                 ledger: ResourceLedger) -> dict[str, Any]:
    out = dict(args)
    for name, arg_rule in rule.args.items():
        if arg_rule.kind == "identity":
            given = out.get(name)
            if given is not None and given != tenant.tenant_id:
                raise GateBlocked("isolation", f"identity argument {name} names another tenant",
                                  {"arg": name})
            out[name] = tenant.tenant_id
        elif arg_rule.kind == "resource" and name in out:
            value = out[name]
            ids = value if isinstance(value, list) else [value]
            for rid in ids:
                if not isinstance(rid, str):
                    raise GateBlocked("isolation", f"resource argument {name} must be a string id")
                if ledger.owner_of(rid) != tenant.tenant_id:
                    # unknown and foreign ids look the same to the caller
                    raise GateBlocked("isolation", f"resource not found for this tenant: {name}",
                                      {"arg": name, "foreign": ledger.owner_of(rid) is not None})
    return out


def _find_keys(obj: Any, keys: set[str], found: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                found.append(v)
            _find_keys(v, keys, found)
    elif isinstance(obj, list):
        for item in obj:
            _find_keys(item, keys, found)


def harvest_resources(tenant: Tenant, rule: ToolRule, texts: list[str], ledger: ResourceLedger) -> list[str]:
    if not rule.resource_out:
        return []
    found: list[str] = []
    for text in texts:
        try:
            _find_keys(json.loads(text), set(rule.resource_out), found)
        except (json.JSONDecodeError, TypeError):
            continue
    for rid in found:
        ledger.record(tenant.tenant_id, rid)
    return found


def _filter_json(obj: Any, foreign: list[str]) -> Any:
    if isinstance(obj, list):
        kept = []
        patterns = [_id_pattern(f) for f in foreign]
        for item in obj:
            blob = json.dumps(item, ensure_ascii=False)
            if any(p.search(blob) for p in patterns):
                continue
            kept.append(_filter_json(item, foreign))
        return kept
    if isinstance(obj, dict):
        return {k: _filter_json(v, foreign) for k, v in obj.items()}
    return obj


def filter_cross_tenant(tenant: Tenant, text: str, ledger: ResourceLedger) -> tuple[str, int]:
    """Drop list items that mention another tenant's resources. Block if that is not enough."""
    foreign = ledger.foreign_ids(tenant.tenant_id, text)
    if not foreign:
        return text, 0
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise GateBlocked("isolation", "result mentions another tenant's resources",
                          {"count": len(foreign)}) from None
    filtered = json.dumps(_filter_json(data, foreign), ensure_ascii=False)
    if ledger.foreign_ids(tenant.tenant_id, filtered):
        raise GateBlocked("isolation", "result mentions another tenant's resources", {"count": len(foreign)})
    return filtered, len(foreign)
