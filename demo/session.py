"""A short, readable demo of what an agent sees through the gateway.

    python -m demo.session

Part 1 is a real MCP client (official SDK) talking to the gateway over stdio,
as tenant acme. The gateway itself starts both upstream MCP servers over
stdio. Part 2 shows two tenants on one gateway core, because on stdio one
process serves one tenant.

The output is saved to results/demo-transcript.txt.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import anyio

ROOT = Path(__file__).resolve().parent.parent
ACME = "acme-demo-key-7f3a"
GLOBEX = "globex-demo-key-91c2"
OUT: list[str] = []


def say(line: str = "") -> None:
    print(line)
    OUT.append(line)


def short(text: str, n: int = 110) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _text(res) -> str:
    return "".join(getattr(c, "text", "") for c in res.content)


def _raw_names() -> list[str]:
    """What the two upstreams offer before the gateway filters anything."""
    from upstreams.evil_server import EvilApp
    from upstreams.notes_server import NotesApp
    return [f"{up}__{t['name']}" for up, app in (("notes", NotesApp()), ("evil", EvilApp()))
            for t in app.list_tools()]


async def part_one(tmp: Path) -> None:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from mcp_tenant_gate.audit import verify_file

    audit = tmp / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_tenant_gate.gateway", "serve", "--audit", str(audit), "--pins", str(tmp / "pins.json")],
        env={"MTG_API_KEY": ACME, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}, cwd=str(ROOT))

    async def call(s, name: str, args: dict) -> str:
        res = await s.call_tool(name, args)
        status = "ERROR" if res.is_error else "ok   "
        say(f"  {status} {name}({short(json.dumps(args), 60)})")
        say(f"         -> {short(_text(res))}")
        return _text(res)

    say("== Part 1: MCP client -> gateway -> 2 upstream MCP servers, all over stdio (tenant: acme)")
    with open(os.devnull, "w") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                tools = sorted(t.name for t in (await s.list_tools()).tools)
                say(f"  tools/list: {len(tools)} tools visible")
                say(f"         {', '.join(tools)}")
                hidden = sorted(set(_raw_names()) - set(tools))
                say(f"  hidden by the gateway (poisoned or shadowing definitions): {', '.join(hidden)}")
                created = await call(s, "notes__create_note", {"title": "plan", "body": "Q4 hiring plan"})
                nid = json.loads(created)["note_id"]
                await call(s, "notes__read_note", {"note_id": nid})
                await call(s, "notes__fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"})
                await call(s, "notes__read_file", {"path": "data/../etc/passwd"})
                await call(s, "evil__lookup", {"topic": "France"})
                await call(s, "evil__customer_lookup", {"name": "Jane"})
                tools2 = sorted(t.name for t in (await s.list_tools()).tools)
                gone = sorted(set(tools) - set(tools2))
                say(f"  tools/list again: {', '.join(gone) or 'nothing'} removed (definition changed after approval)")
                await call(s, "evil__get_weather", {"city": "Oslo"})
    r = verify_file(audit)
    say(f"  audit log: {r.records} records, hash chain ok={r.ok}")


async def part_two() -> None:
    from mcp_tenant_gate.audit import AuditLog
    from mcp_tenant_gate.core import Gateway
    from mcp_tenant_gate.policy import load_policy
    from mcp_tenant_gate.upstream import build_upstreams

    say()
    say("== Part 2: two tenants, one naive notes server behind one gateway core")
    policy = load_policy(ROOT / "tenants.yaml")
    g = Gateway(policy, await build_upstreams(policy, "inprocess"), audit=AuditLog(None))
    await g.list_tools(ACME)
    await g.list_tools(GLOBEX)

    async def call(who: str, key: str, name: str, args: dict) -> str:
        out = await g.call_tool(key, name, args)
        text = out.result["content"][0]["text"]
        tag = f"BLOCKED by {out.layer}" if out.blocked else "ok"
        extra = f" [{', '.join(out.actions)}]" if out.actions else ""
        say(f"  {who:6s} {name}({short(json.dumps(args), 50)}) -> {tag}{extra}")
        say(f"         {short(text)}")
        return text

    created = await call("acme", ACME, "notes__create_note", {"title": "m&a", "body": "acme merger draft"})
    nid = json.loads(created)["note_id"]
    await call("globex", GLOBEX, "notes__read_note", {"note_id": nid})
    await call("globex", GLOBEX, "notes__search_notes", {"query": "merger"})
    await call("globex", GLOBEX, "notes__create_note", {"owner": "acme", "title": "t", "body": "spoof"})
    await call("globex", GLOBEX, "notes__fetch_url", {"url": "https://docs.example.com/"})
    await g.close()


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        await part_one(Path(tmp))
    await part_two()
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "demo-transcript.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")


if __name__ == "__main__":
    anyio.run(main)
