"""PII detection and redaction, configured per tenant.

Categories: email, phone, card, pan, aadhaar.

To keep false positives down, card numbers must pass the Luhn check and
Aadhaar-like numbers must pass the Verhoeff check (the checksum Aadhaar
uses) and must not start with 0 or 1. PAN-like means the Indian PAN shape
(5 letters, 4 digits, 1 letter, with a valid holder-type letter in place 4).
These are pattern rules: they find the common formats, not every way a
person can write a number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(
    r"(?<![\w+])(?<!\w-)(?:\+91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}(?!\w)"  # India mobile
    r"|(?<![\w+])\+(?:[1-9]\d{0,2})[\s\-.]?(?:\(?\d{1,4}\)?[\s\-.]?){2,4}\d{2,4}(?!\d)"  # international with +
    r"|(?<!\d)\(\d{3}\)\s?\d{3}-\d{4}(?!\d)"  # (415) 555-0100
)
CARD = re.compile(r"(?<!\w)(?<!\w-)(?:\d[ \-]?){12,18}\d(?!\w)")
PAN = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")
# Digits glued to letters or joined by a hyphen to a word ("note-960628600311",
# "build-9876543210") are ids, not PII. Same boundary on PHONE and CARD above.
# Found by CI: about 1 in 500 random note ids was being redacted as a phone or Aadhaar.
AADHAAR = re.compile(r"(?<!\w)(?<!\w-)[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\w)")

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_digit(digits: str) -> str:
    """Check digit to append to ``digits`` (used to build test data)."""
    for d in "0123456789":
        if verhoeff_ok(digits + d):
            return d
    raise AssertionError("unreachable")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass
class PiiHit:
    category: str
    start: int
    end: int


def find_pii(text: str, categories: list[str]) -> list[PiiHit]:
    hits: list[PiiHit] = []
    cats = set(categories)
    if "email" in cats:
        hits += [PiiHit("email", m.start(), m.end()) for m in EMAIL.finditer(text)]
    if "aadhaar" in cats:
        for m in AADHAAR.finditer(text):
            if verhoeff_ok(re.sub(r"\D", "", m.group(0))):
                hits.append(PiiHit("aadhaar", m.start(), m.end()))
    if "card" in cats:
        for m in CARD.finditer(text):
            d = re.sub(r"\D", "", m.group(0))
            if 13 <= len(d) <= 19 and luhn_ok(d):
                hits.append(PiiHit("card", m.start(), m.end()))
    if "pan" in cats:
        hits += [PiiHit("pan", m.start(), m.end()) for m in PAN.finditer(text)]
    if "phone" in cats:
        for m in PHONE.finditer(text):
            if len(re.sub(r"\D", "", m.group(0))) >= 10:
                hits.append(PiiHit("phone", m.start(), m.end()))
    # drop overlaps, keep the earliest and longest
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    kept: list[PiiHit] = []
    for h in hits:
        if kept and h.start < kept[-1].end:
            continue
        kept.append(h)
    return kept


def redact(text: str, categories: list[str]) -> tuple[str, dict[str, int]]:
    hits = find_pii(text, categories)
    counts: dict[str, int] = {}
    out = []
    pos = 0
    for h in hits:
        out.append(text[pos:h.start])
        out.append(f"[REDACTED:{h.category}]")
        pos = h.end
        counts[h.category] = counts.get(h.category, 0) + 1
    out.append(text[pos:])
    return "".join(out), counts
