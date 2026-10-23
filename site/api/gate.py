"""Vercel Python function: the playground API.

POST /api/gate                 {"seed", "history", "op"}  -> one gateway operation
POST /api/gate?action=suite    run the 20-attack suite in-process, live
GET  /api/gate                 health and limits

Guards: JSON bodies only, 48 KB cap, op and history validated in
engine/playground.py, and a per-instance token bucket per client IP (the
gateway's own TokenBucket). Serverless instances do not share memory, so this
limit is best effort; the platform's own limits sit behind it.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

SITE = Path(__file__).resolve().parent.parent
if str(SITE) not in sys.path:
    sys.path.insert(0, str(SITE))

from engine import playground  # noqa: E402
from mcp_tenant_gate.ratelimit import TokenBucket  # noqa: E402  (on sys.path via engine)

MAX_BODY = 128 * 1024
_buckets: dict[str, TokenBucket] = {}
_suite_buckets: dict[str, TokenBucket] = {}
_lock = threading.Lock()


def _allow(table: dict[str, TokenBucket], ip: str, capacity: float, refill: float) -> bool:
    with _lock:
        if len(table) > 5000:
            table.clear()
        b = table.get(ip)
        if b is None:
            b = table[ip] = TokenBucket(capacity, refill)
    return b.try_take()


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ip(self) -> str:
        fwd = self.headers.get("x-forwarded-for", "")
        return (fwd.split(",")[0].strip() or self.client_address[0])[:64]

    def do_GET(self) -> None:  # noqa: N802
        self._send(200, {"ok": True, "service": "mcp-tenant-gate playground",
                         "limits": {"body_bytes": MAX_BODY, "history_ops": playground.MAX_HISTORY,
                                    "text_chars": playground.MAX_TEXT, "args_bytes": playground.MAX_ARGS_JSON}})

    def do_POST(self) -> None:  # noqa: N802
        ip = self._ip()
        action = parse_qs(urlsplit(self.path).query).get("action", [""])[0]
        if not _allow(_buckets, ip, 40, 1.0):
            self._send(429, {"error": "slow down: too many requests from this address"})
            return
        if (self.headers.get("content-type") or "").split(";")[0].strip() != "application/json":
            self._send(415, {"error": "send application/json"})
            return
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._send(413, {"error": f"body must be at most {MAX_BODY} bytes"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "body is not valid JSON"})
            return
        started = time.perf_counter()
        try:
            if action == "suite":
                if not _allow(_suite_buckets, ip, 2, 1 / 30):
                    self._send(429, {"error": "the live suite can run about twice a minute per visitor"})
                    return
                out = playground.run_suite()
            else:
                out = playground.handle(body)
        except playground.BadRequest as exc:
            self._send(400, {"error": str(exc)})
            return
        except Exception:
            traceback.print_exc()  # goes to the platform log, never to the client
            self._send(500, {"error": "internal error"})
            return
        out["server_ms"] = round((time.perf_counter() - started) * 1000, 2)
        self._send(200, out)

    def log_message(self, *args) -> None:  # keep request bodies out of logs
        return
