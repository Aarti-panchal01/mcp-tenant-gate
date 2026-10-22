"""Prompt injection checks on tool results (data coming back from upstreams).

A tool result is data, but the model reads it as text and may follow
instructions inside it. Two modes per tenant:

- quarantine: a result with a high severity finding is withheld. The client
  gets a short notice and the audit log keeps a hash of the original.
- wrap: the result is passed on inside explicit untrusted-data markers, with
  invisible characters stripped, so the client and model can treat it as data.

Medium findings are always wrapped, never silently passed.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import Finding
from .text_rules import base64_blobs, imperatives, invisible_chars, strip_invisible, urls

WRAP_OPEN = "<<untrusted_tool_output upstream={upstream}>>"
WRAP_CLOSE = "<<end_untrusted_tool_output>>"


def scan_result(text: str, allow_hosts: list[str] | None = None) -> list[Finding]:
    allow_hosts = allow_hosts or []
    found = invisible_chars(text) + imperatives(text) + base64_blobs(text)
    # plain external links in results are normal (search results, web pages); only flag exfil-shaped ones
    found += [f for f in urls(text, allow_hosts) if f.severity == "high"]
    # secret_word is too common in ordinary data to matter on its own
    return [f for f in found if f.rule != "secret_word"]


@dataclass
class InjectionDecision:
    action: str  # pass | wrap | quarantine
    findings: list[Finding]
    text: str


def decide(text: str, mode: str, upstream: str, allow_hosts: list[str] | None = None) -> InjectionDecision:
    findings = scan_result(text, allow_hosts)
    if not findings:
        return InjectionDecision("pass", [], text)
    high = any(f.severity == "high" for f in findings)
    if high and mode == "quarantine":
        notice = (f"[mcp-tenant-gate] Result from {upstream} withheld: it contained instructions aimed at the "
                  f"model ({', '.join(sorted({f.rule for f in findings}))}). Ask an operator to review the "
                  f"quarantined copy if you need it.")
        return InjectionDecision("quarantine", findings, notice)
    wrapped = f"{WRAP_OPEN.format(upstream=upstream)}\n{strip_invisible(text)}\n{WRAP_CLOSE}"
    return InjectionDecision("wrap", findings, wrapped)
