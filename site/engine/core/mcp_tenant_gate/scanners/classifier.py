"""Second injection layer: a small linear classifier, pure Python at run time.

The weights in `clf_model.json` come from `python -m evals.train_classifier`,
which trains on the TRAIN split of deepset/prompt-injections only (see
evals/data/SPLIT.json). Features are binary word 1-2 grams and character 3-5
grams over normalised text (normalize.py). Scoring a result costs well under a
millisecond. No network, no extra dependency (scikit-learn is needed only to
retrain).

Long text is cut into windows of at most WINDOW characters at sentence ends and
the highest window score is used, so a long benign document does not dilute a
short injected paragraph.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path

from . import Finding
from .normalize import normalise_text

MODEL_PATH = Path(__file__).with_name("clf_model.json")
WINDOW = 400
_WORD = re.compile(r"\w+", re.UNICODE)
_SENT = re.compile(r"(?<=[.!?\n])\s+")


def features(text: str) -> set[str]:
    """Binary features of already normalised text."""
    words = _WORD.findall(text)
    f: set[str] = set(words)
    f.update(a + " " + b for a, b in zip(words, words[1:]))
    for w in words:
        p = f"^{w}$"
        for n in (3, 4, 5):
            for i in range(len(p) - n + 1):
                f.add("#" + p[i:i + n])
    return f


def windows(text: str, size: int = WINDOW) -> list[str]:
    if len(text) <= size:
        return [text]
    out, cur = [], ""
    for s in _SENT.split(text):
        if cur and len(cur) + len(s) + 1 > size:
            out.append(cur)
            cur = s
        else:
            cur = f"{cur} {s}".strip()
    if cur:
        out.append(cur)
    return [w[:size * 3] for w in out]


@lru_cache(maxsize=1)
def load_model() -> dict | None:
    if not MODEL_PATH.exists():
        return None
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def score_window(norm: str, model: dict) -> float:
    w = model["weights"]
    hits = [w[f] for f in features(norm) if f in w]
    z = model["bias"] + (sum(hits) / math.sqrt(len(hits)) if hits else 0.0)
    return 1 / (1 + math.exp(-z))


def score(text: str, model: dict | None = None) -> float:
    """Probability-like score in [0, 1] that `text` is an injection; max over windows."""
    model = model or load_model()
    if model is None:
        return 0.0
    norm = normalise_text(text)
    return max(score_window(w, model) for w in windows(norm))


def classify(text: str) -> list[Finding]:
    model = load_model()
    if model is None or not text.strip():
        return []
    s = score(text, model)
    if s >= model["t_high"]:
        return [Finding("clf_injection", "high", f"score {s:.2f}")]
    if s >= model["t_low"]:
        return [Finding("clf_suspect", "medium", f"score {s:.2f}")]
    return []
