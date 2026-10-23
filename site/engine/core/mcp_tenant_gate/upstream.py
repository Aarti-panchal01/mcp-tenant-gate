"""Upstream adapters. The gateway core only needs ``list_tools`` and ``call_tool``
returning plain dicts, so the same core runs against in-process objects (fast,
deterministic tests) and real MCP servers over stdio (the official SDK)."""

from __future__ import annotations

import importlib
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parent.parent


class Upstream(Protocol):
    name: str

    async def list_tools(self) -> list[dict[str, Any]]: ...

    async def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]: ...

    async def close(self) -> None: ...


class InProcessUpstream:
    def __init__(self, name: str, app: Any):
        self.name = name
        self.app = app

    @classmethod
    def from_module(cls, name: str, module: str) -> "InProcessUpstream":
        mod_name, _, cls_name = module.partition(":")
        mod = importlib.import_module(mod_name)
        return cls(name, getattr(mod, cls_name)())

    async def list_tools(self) -> list[dict[str, Any]]:
        return [dict(t) for t in self.app.list_tools()]

    async def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.app.call_tool(name, dict(args))

    async def close(self) -> None:
        return None


class StdioUpstream:
    """An MCP server subprocess spoken to over stdio with the official SDK client."""

    def __init__(self, name: str, command: str, args: list[str], env: dict[str, str] | None = None,
                 cwd: str | Path | None = None, timeout: float = 30.0):
        self.name = name
        self.command = sys.executable if command in ("python", "python3") else command
        self.args = args
        self.env = env
        self.cwd = cwd or ROOT
        self.timeout = timeout
        self._stack: AsyncExitStack | None = None
        self._session = None

    async def start(self) -> "StdioUpstream":
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        env = dict(self.env or {})
        env.setdefault("PYTHONPATH", str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        env.setdefault("PYTHONIOENCODING", "utf-8")
        params = StdioServerParameters(command=self.command, args=self.args, env=env, cwd=str(self.cwd))
        self._stack = AsyncExitStack()
        errlog = self._stack.enter_context(open(os.devnull, "w"))  # closed with the stack, not leaked
        read, write = await self._stack.enter_async_context(stdio_client(params, errlog=errlog))
        self._session = await self._stack.enter_async_context(
            ClientSession(read, write, read_timeout_seconds=self.timeout))
        await self._session.initialize()
        return self

    async def list_tools(self) -> list[dict[str, Any]]:
        res = await self._session.list_tools()
        return [t.model_dump(by_alias=True, exclude_none=True) for t in res.tools]

    async def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = await self._session.call_tool(name, args)
        data = res.model_dump(by_alias=True, exclude_none=True)
        return {"content": data.get("content", []), "isError": bool(data.get("isError", False))}

    async def close(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None


async def build_upstreams(policy, mode: str = "inprocess") -> dict[str, Upstream]:
    """mode is 'inprocess' (needs ``module`` in the policy) or 'stdio'."""
    if mode not in ("inprocess", "stdio"):
        raise ValueError(f"unknown upstream mode {mode!r}")
    out: dict[str, Upstream] = {}
    try:
        for name, spec in policy.upstreams.items():
            if mode == "inprocess":
                if not spec.module:
                    raise ValueError(f"upstream {name} has no module for in-process mode")
                out[name] = InProcessUpstream.from_module(name, spec.module)
            else:
                out[name] = await StdioUpstream(name, spec.command, spec.args).start()
    except BaseException:
        for up in reversed(list(out.values())):  # do not leak subprocesses started so far
            await up.close()
        raise
    return out
