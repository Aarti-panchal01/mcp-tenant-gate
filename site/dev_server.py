"""Local preview: serves the static site and /api/gate with the same handler Vercel runs.

    python site/dev_server.py      # then open http://127.0.0.1:8765
"""
from __future__ import annotations

import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SITE = Path(__file__).resolve().parent
sys.path.insert(0, str(SITE))
from api.gate import handler as ApiHandler  # noqa: E402


class Dev(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(SITE), **kw)

    def _api(self) -> bool:
        return self.path.startswith("/api/gate")

    def do_GET(self):
        if self._api():
            return ApiHandler.do_GET(self)
        return super().do_GET()

    def do_POST(self):
        if self._api():
            return ApiHandler.do_POST(self)
        self.send_error(405)

    _send = ApiHandler._send
    _ip = ApiHandler._ip


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Dev).serve_forever()
