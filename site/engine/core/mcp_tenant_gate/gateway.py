"""The gateway as a real MCP server (stdio), in front of real MCP upstreams (stdio).

    MTG_API_KEY=acme-demo-key-7f3a python -m mcp_tenant_gate.gateway serve

The MCP client (Claude Desktop, an agent, the e2e test) starts this process
and speaks MCP to it on stdin/stdout. The gateway starts each upstream from
tenants.yaml as its own subprocess and speaks MCP to it as a client.

Auth on stdio: stdio has no headers, so the API key comes from the
``MTG_API_KEY`` environment variable of the gateway process, which the
client's config sets. One gateway process serves one tenant. A network
transport (streamable HTTP with a bearer header) would let one process
serve many tenants; the core already supports that, the transport is not
built here.

Other commands:
    python -m mcp_tenant_gate.gateway hash-key <key>      print the SHA-256 for tenants.yaml
    python -m mcp_tenant_gate.gateway verify-audit <file> check the audit hash chain
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _serve(policy_path: str, audit_path: str, pins_path: str) -> None:
    import anyio
    import mcp_types as types
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    from .audit import AuditLog
    from .core import Gateway
    from .judge import judge_from_env
    from .policy import load_policy
    from .scanners.tool_poisoning import PinStore
    from .upstream import build_upstreams

    from .errors import GateBlocked

    api_key = os.environ.get("MTG_API_KEY")
    policy = load_policy(policy_path)
    try:
        policy.authenticate(api_key)  # fail fast on a bad key, before starting upstreams
    except GateBlocked as exc:
        print(f"mcp-tenant-gate: {exc.reason} (set MTG_API_KEY)", file=sys.stderr)
        sys.exit(2)

    async def main() -> None:
        upstreams = await build_upstreams(policy, mode="stdio")
        gate = Gateway(policy, upstreams, audit=AuditLog(audit_path), pins=PinStore(pins_path),
                       judge=judge_from_env())

        async def on_list(ctx, params):
            tools = await gate.list_tools(api_key)
            return types.ListToolsResult(tools=[types.Tool.model_validate(t) for t in tools])

        async def on_call(ctx, params):
            outcome = await gate.call_tool(api_key, params.name, dict(params.arguments or {}))
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=c["text"]) for c in outcome.result["content"]],
                is_error=outcome.result.get("isError", False))

        server = Server("mcp-tenant-gate", version="0.1.0", on_list_tools=on_list, on_call_tool=on_call)
        try:
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
        finally:
            await gate.close()

    anyio.run(main)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp_tenant_gate.gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the gateway as an MCP server on stdio")
    s.add_argument("--policy", default=str(ROOT / "tenants.yaml"))
    s.add_argument("--audit", default=str(ROOT / "runtime" / "audit.jsonl"))
    s.add_argument("--pins", default=str(ROOT / "runtime" / "pins.json"))
    h = sub.add_parser("hash-key", help="print the SHA-256 of an API key for tenants.yaml")
    h.add_argument("key")
    v = sub.add_parser("verify-audit", help="verify the audit log hash chain")
    v.add_argument("path")
    v.add_argument("--head", default=None, help="expected latest hash, if you anchored it somewhere")
    a = ap.parse_args(argv)

    if a.cmd == "hash-key":
        from .policy import hash_key
        print(hash_key(a.key))
        return 0
    if a.cmd == "verify-audit":
        from .audit import verify_file
        r = verify_file(a.path, a.head)
        print(f"ok={r.ok} records={r.records}" + ("" if r.ok else f" bad_line={r.bad_line} reason={r.reason}"))
        return 0 if r.ok else 1
    _serve(a.policy, a.audit, a.pins)
    return 0


if __name__ == "__main__":
    sys.exit(main())
