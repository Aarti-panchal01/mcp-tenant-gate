"""A benign but naive notes server.

It is deliberately single-tenant: it trusts whatever ``owner`` it is given,
``search_notes`` searches everyone's notes, ``read_file`` resolves paths
without checks and ``fetch_url`` fetches anything. Everything is simulated
in memory (no real disk or network), so the unsafe behaviour is safe to demo.
The point is that the gateway adds tenant isolation in front of a server
that has none.

Run as an MCP server: ``python -m upstreams.notes_server``
"""

from __future__ import annotations

import posixpath
import uuid
from typing import Any

from upstreams.common import obj_schema, serve_stdio, text_result

FAKE_FS = {
    "data/handbook.txt": "Office hours are 9 to 5. Expense reports go to finance by the 5th.",
    "data/reports/q3.txt": "Q3 revenue grew 12 percent over Q2.",
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsvc:x:1000:1000::/home/svc:/bin/sh",
    "secrets/prod.env": "DATABASE_URL=postgres://admin:hunter2@db.internal/prod",
}

FAKE_WEB = {
    "docs.example.com": "Example Docs: the export API returns CSV by default. Pass format=json for JSON.",
    "api.acme.example": '{"status": "ok", "region": "eu-west"}',
    "169.254.169.254": '{"AccessKeyId": "ASIAFAKEKEY", "SecretAccessKey": "fake/secret", "Token": "fake"}',
    "127.0.0.1": "internal admin panel: delete_all_users enabled",
    "localhost": "internal admin panel: delete_all_users enabled",
}


class NotesApp:
    def __init__(self) -> None:
        self.notes: dict[str, dict[str, Any]] = {}

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": "create_note", "description": "Create a note for an owner. Returns the new note id.",
             "inputSchema": obj_schema({"owner": {"type": "string"}, "title": {"type": "string"},
                                        "body": {"type": "string"}})},
            {"name": "read_note", "description": "Read one note by its id.",
             "inputSchema": obj_schema({"note_id": {"type": "string"}})},
            {"name": "list_notes", "description": "List the ids and titles of an owner's notes.",
             "inputSchema": obj_schema({"owner": {"type": "string"}})},
            {"name": "search_notes", "description": "Search note titles and bodies for a word.",
             "inputSchema": obj_schema({"query": {"type": "string"}})},
            {"name": "read_file", "description": "Read a text file from the shared document folder.",
             "inputSchema": obj_schema({"path": {"type": "string", "description": "Relative path, for example data/handbook.txt"}})},
            {"name": "fetch_url", "description": "Fetch a web page and return its text.",
             "inputSchema": obj_schema({"url": {"type": "string"}})},
        ]

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "create_note":
            nid = f"note-{uuid.uuid4().hex[:12]}"
            self.notes[nid] = {"note_id": nid, "owner": args["owner"], "title": args["title"], "body": args["body"]}
            return text_result({"note_id": nid, "title": args["title"]})
        if name == "read_note":
            note = self.notes.get(args.get("note_id", ""))
            return text_result(note) if note else text_result("note not found", True)
        if name == "list_notes":
            return text_result([{"note_id": n["note_id"], "title": n["title"]}
                                for n in self.notes.values() if n["owner"] == args.get("owner")])
        if name == "search_notes":
            q = str(args.get("query", "")).lower()
            # naive: searches every owner's notes
            return text_result([n for n in self.notes.values()
                                if q in n["title"].lower() or q in n["body"].lower()])
        if name == "read_file":
            # naive: normalises "data/../etc/passwd" to "etc/passwd" and serves it
            path = posixpath.normpath(str(args.get("path", ""))).lstrip("/")
            content = FAKE_FS.get(path)
            return text_result(content) if content else text_result("file not found", True)
        if name == "fetch_url":
            from urllib.parse import urlsplit
            host = (urlsplit(args.get("url", "")).hostname or "").lower()
            return text_result(FAKE_WEB.get(host, f"<html>page at {host}</html>"))
        return text_result(f"unknown tool {name}", True)


if __name__ == "__main__":
    serve_stdio(NotesApp(), "notes")
