"""Low-level text rules shared by the description and result scanners."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from urllib.parse import urlsplit

from . import Finding

# Zero-width, bidi controls, word joiner, BOM, soft hyphen, Mongolian vowel separator.
INVISIBLE = set(
    "​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤⁦⁧⁨⁩﻿­᠎"
)
TAG_START, TAG_END = 0xE0000, 0xE007F  # Unicode "tag" block, used to hide ASCII text


def invisible_chars(text: str) -> list[Finding]:
    found: list[Finding] = []
    hidden_tag_text = "".join(chr(ord(c) - TAG_START) for c in text if TAG_START <= ord(c) <= TAG_END
                              and 0x20 <= ord(c) - TAG_START < 0x7F)
    if hidden_tag_text:
        found.append(Finding("unicode_tag_smuggling", "high", f"hidden text: {hidden_tag_text}"))
    zw = [c for c in text if c in INVISIBLE]
    if zw:
        names = sorted({unicodedata.name(c, hex(ord(c))) for c in zw})
        found.append(Finding("invisible_unicode", "high" if len(zw) >= 3 else "medium",
                             f"{len(zw)} invisible chars: {', '.join(names)[:80]}"))
    other_cf = [c for c in text if unicodedata.category(c) == "Cf" and c not in INVISIBLE
                and not TAG_START <= ord(c) <= TAG_END]
    if other_cf:
        found.append(Finding("format_control_chars", "medium", f"{len(other_cf)} format control chars"))
    return found


def strip_invisible(text: str) -> str:
    return "".join(c for c in text if c not in INVISIBLE and not TAG_START <= ord(c) <= TAG_END)


def normalise(text: str) -> str:
    """Fold look-alike forms so 'ｉｇｎｏｒｅ' and 'i​gnore' match plain rules."""
    return unicodedata.normalize("NFKC", strip_invisible(text)).lower()


# Phrases an honest tool description or tool result has no reason to contain.
IMPERATIVE_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("ignore_previous", "high", re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system|original)\b"
        r"[^.\n]{0,20}\b(instructions?|prompts?|rules|messages?|guidelines|context)\b")),
    ("hidden_instruction_tag", "high", re.compile(
        r"<\s*/?\s*(important|system|instructions?|secret|admin|hidden|sudo)\s*>")),
    ("conceal_from_user", "high", re.compile(
        # "don't forget to tell the user" is a reminder, not concealment
        r"\b(do not|don't|never|without)\b(?!\s+(forget|hesitate|fail)\b)[^.\n]{0,30}"
        r"\b(tell|inform|mention|show|reveal|alert|notify|let)\b"
        r"[^.\n]{0,20}\b(the )?(user|human|operator|them)\b")),
    ("secret_file_access", "high", re.compile(
        r"(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|/etc/passwd|/etc/shadow|(?<![\w.])\.env\b|\.npmrc"
        r"|\.git-credentials|mcp\.json|claude_desktop_config)")),
    ("secret_word", "low", re.compile(r"\b(private key|api[_ ]?keys?|access[_ ]tokens?|passwords?)\b")),
    ("role_override", "high", re.compile(
        # "you are now subscribed" and "from now on you can find..." are ordinary text
        r"\b(you are now (in )?(an? |the )?([\w-]+ )?(mode|assistant|agent|admin|developer|unrestricted|jailbroken)\b"
        r"|from now on,? you (must|will|should|are to|have to)\b"
        r"|act as (an? )?(admin|system|developer|root)|new instructions?:|system prompt:)")),
    ("tool_redirect", "medium", re.compile(
        r"\b(instead of|rather than|do not use|don't use|never use)\b[^.\n]{0,40}\b(tool|function|server|read_note|"
        r"send|email|notes)\b")),
    ("cross_tool_instruction", "medium", re.compile(
        r"\b(before|after|when) (using|calling|you use|you call)\b[^.\n]{0,60}\b(you must|always|first)\b")),
    ("exfil_verb", "medium", re.compile(
        r"\b(send|forward|upload|post|transmit|exfiltrate|leak|copy)\b[^.\n]{0,50}\b(conversation|chat history|"
        r"all (notes|messages|files|data)|credentials|secrets|tokens?|contents of)\b")),
    ("fake_tool_call", "high", re.compile(r"<\s*(tool_call|function_call|invoke|tool_use)\b|\"tool_calls\"\s*:")),
]

URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s<>\"')\]]+", re.IGNORECASE)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def imperatives(text: str) -> list[Finding]:
    norm = normalise(text)
    out = []
    for rule, sev, pat in IMPERATIVE_RULES:
        m = pat.search(norm)
        if m:
            out.append(Finding(rule, sev, m.group(0)))
    return out


def urls(text: str, allow_hosts: list[str]) -> list[Finding]:
    out = []
    norm = strip_invisible(text)
    for m in MD_IMAGE_RE.finditer(norm):
        if "?" in m.group(1) or "{" in m.group(1):
            out.append(Finding("markdown_image_exfil", "high", m.group(1)))
    for m in URL_RE.finditer(norm):
        url = m.group(0)
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        if any(host == h or host.endswith("." + h) for h in allow_hosts):
            continue
        # A URL with a placeholder ("?d={conversation}") is a template for leaking
        # data: high. A plain query string is normal in real links (search
        # results, docs), so it is only medium.
        templated = bool(re.search(r"[{<]\s*\w+|\$\{|%s|=\s*<", url))
        if templated:
            out.append(Finding("exfil_url", "high", url))
        elif "?" in url:
            out.append(Finding("url_with_query", "medium", url))
        else:
            out.append(Finding("external_url", "low", url))
    return out


def base64_blobs(text: str) -> list[Finding]:
    out = []
    for m in B64_RE.finditer(strip_invisible(text)):
        blob = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", blob):
            continue  # hex digests (sha256 etc.) are normal
        if not (re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob)):
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / max(1, len(raw))
        if printable > 0.9:
            decoded = raw.decode("ascii", "replace")
            inner = imperatives(decoded)
            sev = "high" if inner else "medium"
            out.append(Finding("base64_blob", sev, f"decodes to: {decoded[:60]}"))
        else:
            out.append(Finding("base64_blob", "low", blob[:40]))
    return out
