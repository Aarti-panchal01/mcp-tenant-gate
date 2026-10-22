"""Text normalisation for the second injection layer.

Folds the cheap obfuscations so a classifier or rule sees plain words:
look-alike letters (Cyrillic / Greek), full-width forms, zero-width characters,
letters spaced apart ("i g n o r e"), percent encoding, and base64 or hex
payloads, whose decoded text is appended to the original.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote

from .text_rules import B64_RE, strip_invisible

# Cyrillic and Greek letters that look like Latin ones. Small on purpose.
_PAIRS = (
    "а=a е=e о=o р=p с=c у=y х=x і=i ј=j ѕ=s һ=h ԁ=d ɡ=g к=k м=m н=h т=t в=b "
    "ο=o α=a ε=e ι=i κ=k ν=v ρ=p τ=t υ=u χ=x "
    "А=A Е=E О=O Р=P С=C Т=T Х=X І=I М=M Н=H "
    "Α=A Β=B Ε=E Ι=I Κ=K Μ=M Ν=N Ο=O Ρ=P Τ=T"
)
_HOMOGLYPHS = str.maketrans(dict(p.split("=") for p in _PAIRS.split()))
_SPACED = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ .\-_]){3,}[A-Za-z](?![A-Za-z])")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
MAX_DECODED = 2000


def _printable_ascii(raw: bytes) -> str | None:
    if not raw:
        return None
    if sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw) < 0.9:
        return None
    return raw.decode("ascii", "replace")


def decoded_payloads(text: str) -> list[str]:
    """Text hidden in base64, hex or percent encoding inside `text`."""
    out: list[str] = []
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", blob):
            continue
        try:
            s = _printable_ascii(base64.b64decode(blob + "=" * (-len(blob) % 4)))
        except (binascii.Error, ValueError):
            s = None
        if s:
            out.append(s)
    for m in _HEX.finditer(text):
        try:
            s = _printable_ascii(bytes.fromhex(m.group(0)))
        except ValueError:
            s = None
        if s and re.search(r"[A-Za-z]{3}", s):
            out.append(s)
    for m in _PCT.finditer(text):
        s = _printable_ascii(unquote(m.group(0), errors="replace").encode("utf-8", "replace"))
        if s:
            out.append(s)
    return out


def normalise_text(text: str, decode: bool = True) -> str:
    """Lower-case, folded text. Decoded payloads are appended after a newline."""
    t = strip_invisible(text)
    t = t.translate(_HOMOGLYPHS)
    t = unicodedata.normalize("NFKC", t)
    t = _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), t)
    extra = ""
    if decode:
        extra = "\n".join(decoded_payloads(t))[:MAX_DECODED]
    t = t + ("\n" + extra if extra else "")
    return " ".join(t.lower().split())
