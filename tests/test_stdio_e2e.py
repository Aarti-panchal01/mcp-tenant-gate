"""End to end over real stdio: an MCP client (official SDK) starts the gateway
as an MCP server, and the gateway starts both upstreams as MCP servers.

    client --stdio--> gateway --stdio--> notes_server
                                 \\--stdio--> evil_server

Skipped cleanly if subprocess stdio is not available on the machine.
"""

import json
import os
import sys

import anyio
import pytest

from conftest import ACME, ROOT

pytestmark = pytest.mark.e2e


async def _session(tmp_path, key, body):
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = {"MTG_API_KEY": key, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_tenant_gate.gateway", "serve", "--audit", str(tmp_path / "audit.jsonl"),
              "--pins", str(tmp_path / "pins.json")],
        env=env, cwd=str(ROOT))
    with anyio.fail_after(90):
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as s:
                    await s.initialize()
                    return await body(s)


def _text(res):
    return "".join(c.text for c in res.content)


def test_gateway_over_stdio_end_to_end(tmp_path):
    async def body(s):
        tools = {t.name for t in (await s.list_tools()).tools}
        create = await s.call_tool("notes__create_note", {"title": "e2e", "body": "hello over stdio"})
        nid = json.loads(_text(create))["note_id"]
        read = await s.call_tool("notes__read_note", {"note_id": nid})
        ssrf = await s.call_tool("notes__fetch_url", {"url": "http://169.254.169.254/latest/"})
        inj = await s.call_tool("evil__lookup", {"topic": "France"})
        poisoned = await s.call_tool("evil__add_numbers", {"a": 1, "b": 2})
        tools2 = {t.name for t in (await s.list_tools()).tools}  # evil rewrites get_weather now
        rug = await s.call_tool("evil__get_weather", {"city": "Oslo"})
        return tools, read, ssrf, inj, poisoned, tools2, rug

    try:
        tools, read, ssrf, inj, poisoned, tools2, rug = anyio.run(_session, tmp_path, ACME, body)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"stdio subprocesses unavailable: {exc}")

    assert "notes__read_note" in tools and "evil__add_numbers" not in tools
    assert not read.is_error and "hello over stdio" in _text(read)
    assert ssrf.is_error and "SSRF" in _text(ssrf)
    assert inj.is_error and "maintenance mode" not in _text(inj)
    assert poisoned.is_error
    assert "evil__get_weather" in tools and "evil__get_weather" not in tools2
    assert rug.is_error and "quarantined" in _text(rug)

    from mcp_tenant_gate.audit import verify_file
    r = verify_file(tmp_path / "audit.jsonl")
    assert r.ok and r.records >= 8


def test_gateway_refuses_unknown_key_at_startup(tmp_path):
    async def body(s):
        return await s.list_tools()

    with pytest.raises(BaseException):
        anyio.run(_session, tmp_path, "not-a-real-key", body)
