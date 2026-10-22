"""Train the second-layer classifier on the TRAIN split only.

    python -m evals.train_classifier

Needs scikit-learn and scipy (dev only). Chooses C and the two thresholds from
5-fold cross validation INSIDE the train split. Test rows are dropped the moment
the file is read and are never used here. Writes
mcp_tenant_gate/scanners/clf_model.json.

Thresholds: t_high is the out-of-fold score that leaves at most 0.5% of train
benign rows above it (withhold); t_low leaves at most 3% (wrap in
untrusted-data markers).
"""

from __future__ import annotations

import json
import math
from collections import Counter

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold

from evals.injection_eval import DATA, stdlib_side
from mcp_tenant_gate.scanners.classifier import MODEL_PATH, features
from mcp_tenant_gate.scanners.normalize import normalise_text

SEED = 7


def train_rows() -> list[dict]:
    with DATA.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f]
    return [r for r in rows if r["split"] == "train"]


def extra_negatives() -> list[str]:
    """Dev-only benign text added to every training fold, never used for thresholds or scores:
    my own benign sentences (evals/data/dev_benign.txt) and Python stdlib docstring paragraphs
    from modules whose file name hashes to an even number. Odd modules are the benign eval."""
    import random

    from evals.injection_eval import dev_benign, stdlib_paragraphs_by_file
    out = list(dev_benign())
    paras = [p for f, p in stdlib_paragraphs_by_file() if stdlib_side(f) == "train"]
    random.Random(SEED).shuffle(paras)
    return out + paras[:900]


def build(feats: list[set[str]], vocab: dict[str, int]) -> csr_matrix:
    ind, ptr, val = [], [0], []
    for fs in feats:
        ids = [vocab[f] for f in fs if f in vocab]
        v = 1 / math.sqrt(len(ids)) if ids else 0.0
        ind += ids
        val += [v] * len(ids)
        ptr.append(len(ind))
    return csr_matrix((val, ind, ptr), shape=(len(feats), len(vocab)))


def vocab_from(feats: list[set[str]], min_df: int = 2) -> dict[str, int]:
    c = Counter(f for fs in feats for f in fs)
    return {f: i for i, f in enumerate(sorted(f for f, n in c.items() if n >= min_df))}


def cv_oof(feats, y, C, extra):
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(5, shuffle=True, random_state=SEED).split(feats, y):
        tf = [feats[i] for i in tr] + extra
        voc = vocab_from(tf)
        m = LogisticRegression(C=C, max_iter=2000, class_weight="balanced")
        m.fit(build(tf, voc), np.concatenate([y[tr], np.zeros(len(extra), dtype=int)]))
        oof[va] = m.predict_proba(build([feats[i] for i in va], voc))[:, 1]
    return oof


def main() -> None:
    rows = train_rows()
    assert all(r["split"] == "train" for r in rows)
    feats = [features(normalise_text(r["text"])) for r in rows]
    y = np.array([r["label"] for r in rows])
    extra = [features(normalise_text(t)) for t in extra_negatives()]
    print(f"{len(rows)} train rows + {len(extra)} extra benign texts")
    best = None
    for C in (1, 3, 10, 30, 100):
        oof = cv_oof(feats, y, C, extra)
        neg = np.sort(oof[y == 0])
        t = float(neg[int(len(neg) * 0.995)])
        rec = float((oof[y == 1] > t).mean())
        print(f"C={C:<4} out-of-fold recall at 0.5% FPR: {rec:.3f}  (t={t:.3f})")
        if best is None or rec > best[0]:
            best = (rec, C, oof)
    rec, C, oof = best
    neg = np.sort(oof[y == 0])
    t_high = float(neg[int(len(neg) * 0.995)])
    t_low = min(float(neg[int(len(neg) * 0.97)]), t_high)
    print(f"chosen C={C}  t_high={t_high:.3f}  t_low={t_low:.3f}  cv recall@t_high={(oof[y == 1] > t_high).mean():.3f}"
          f"  @t_low={(oof[y == 1] > t_low).mean():.3f}")
    allf = feats + extra
    voc = vocab_from(allf)
    m = LogisticRegression(C=C, max_iter=2000, class_weight="balanced").fit(
        build(allf, voc), np.concatenate([y, np.zeros(len(extra), dtype=int)]))
    w = {f: round(float(m.coef_[0][i]), 3) for f, i in voc.items() if abs(m.coef_[0][i]) >= 0.05}
    model = {"kind": "logreg-binary-ngrams", "trained_on": "deepset/prompt-injections train split (546 rows) + dev benign texts",
             "C": C, "seed": SEED, "bias": round(float(m.intercept_[0]), 4),
             "t_high": round(t_high, 4), "t_low": round(t_low, 4), "weights": w}
    MODEL_PATH.write_text(json.dumps(model, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {MODEL_PATH} ({len(w)} weights, {MODEL_PATH.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
