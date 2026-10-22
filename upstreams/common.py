"""Shared helpers so each upstream is a plain Python object that can run two ways:
in-process (tests, fast attack suite) or as a real MCP server over stdio."""

from __future__ import annotations

import json
from typing import Any


def text_result(payload: Any, is_error: bool = False) -> dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def obj_schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required or list(props),
            "additionalProperties": False}


def serve_stdio(app: Any, name: str) -> None:
    """Run ``app`` as an MCP server on stdin/stdout using the official SDK."""
    import anyio
    import mcp_types as types
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    async def on_list(ctx, params):
        return types.ListToolsResult(tools=[types.Tool.model_validate(t) for t in app.list_tools()])

    async def on_call(ctx, params):
        res = app.call_tool(params.name, dict(params.arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=c["text"]) for c in res["content"]],
            is_error=res.get("isError", False))

    async def main():
        server = Server(name, on_list_tools=on_list, on_call_tool=on_call)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(main)
