"""Property-style isolation tests: random interleavings of two tenants, one invariant.

No tenant ever sees another tenant's note body or note id, whatever order
the calls come in. Seeds are fixed so a failure is reproducible.
"""

import json
import random

import anyio
import pytest

from conftest import ACME, GLOBEX
from mcp_tenant_gate.core import Gateway
from mcp_tenant_gate.isolation import ResourceLedger, filter_cross_tenant
from mcp_tenant_gate.ratelimit import FakeClock, RateLimiter
from mcp_tenant_gate.upstream import build_upstreams

KEYS = {"acme": ACME, "globex": GLOBEX}


async def _random_session(policy, seed, steps=120):
    rng = random.Random(seed)
    clock = FakeClock()
    gate = Gateway(policy, await build_upstreams(policy), limiter=RateLimiter(clock))
    for key in KEYS.values():
        await gate.list_tools(key)
    owned = {"acme": [], "globex": []}
    for step in range(steps):
        clock.advance(1.0)
        me = rng.choice(["acme", "globex"])
        other = "globex" if me == "acme" else "acme"
        op = rng.choice(["create", "create", "list", "search", "read_own", "read_other", "spoof"])
        if op == "create":
            out = await gate.call_tool(KEYS[me], "notes__create_note",
                                       {"title": f"{me} t{step}", "body": f"secret-{me}-{step}"})
            assert not out.blocked, out.reason
            owned[me].append(json.loads(out.result["content"][0]["text"])["note_id"])
        elif op == "list":
            out = await gate.call_tool(KEYS[me], "notes__list_notes", {})
        elif op == "search":
            out = await gate.call_tool(KEYS[me], "notes__search_notes", {"query": "secret"})
        elif op == "read_own" and owned[me]:
            out = await gate.call_tool(KEYS[me], "notes__read_note", {"note_id": rng.choice(owned[me])})
            assert not out.blocked
        elif op == "read_other" and owned[other]:
            out = await gate.call_tool(KEYS[me], "notes__read_note", {"note_id": rng.choice(owned[other])})
            assert out.blocked and out.layer == "isolation"
        elif op == "spoof":
            out = await gate.call_tool(KEYS[me], "notes__list_notes", {"owner": other})
            assert out.blocked
        else:
            continue
        text = "".join(c["text"] for c in out.result["content"])
        assert f"secret-{other}-" not in text, (seed, step, op, text[:200])
        for nid in owned[other]:
            assert nid not in text, (seed, step, op)
    await gate.close()


@pytest.mark.parametrize("seed", range(6))
def test_random_interleavings_never_leak(policy, seed):
    anyio.run(_random_session, policy, seed)


def test_filter_matches_whole_ids_only(policy):
    ledger = ResourceLedger()
    ledger.record("globex", "note-1")
    acme = policy.tenants["acme"]
    text = json.dumps([{"note_id": "note-12", "t": "mine"}, {"note_id": "note-1", "t": "theirs"}])
    out, dropped = filter_cross_tenant(acme, text, ledger)
    assert dropped == 1 and "note-12" in out and "theirs" not in out


def test_upstream_returning_foreign_id_on_create_is_blocked(policy):
    from mcp_tenant_gate.errors import GateBlocked
    ledger = ResourceLedger()
    ledger.record("globex", "note-aaaaaaaaaaaa")
    with pytest.raises(GateBlocked, match="owned by another tenant"):
        ledger.record("acme", "note-aaaaaaaaaaaa")
