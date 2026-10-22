"""Held-out eval of the result scanner on a public prompt injection dataset.

    python -m evals.injection_eval              # pattern rules only
    python -m evals.injection_eval --judge      # also ask the LLM judge (needs MTG_JUDGE + key)

Data: deepset/prompt-injections (Hugging Face, Apache-2.0), 662 rows, all
splits, snapshot in evals/data/. The first rules were written without seeing
any of it. Then new rules were tuned on the train split only, and the test
split was run once at the end. The report prints misses and false flags from
the train split only, so tuning never reads test rows.

Caveat: these are direct user prompts, not tool results. The gateway scans
tool results, so this measures the text rules on someone else's idea of an
injection, which is the point: it is not my own test set.

Writes results/injection-eval.md and results/injection-eval.json.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import sysconfig
import time
from pathlib import Path

from mcp_tenant_gate.judge import judge_from_env
from mcp_tenant_gate.scanners.injection import decide

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "evals" / "data" / "deepset_prompt_injections.jsonl"
SOURCE = "https://huggingface.co/datasets/deepset/prompt-injections (revision 4f61ecb)"

DE_WORDS = {"der", "die", "das", "und", "ist", "nicht", "ich", "sie", "mit", "für", "auf", "ein", "eine",
            "wie", "was", "zu", "den", "dem", "von", "bitte", "alle", "vergiss", "du", "mir", "sind", "auch"}


def language(text: str) -> str:
    """Rough split: German if it has umlauts/ß or 3+ common German words. Good enough for this dataset."""
    words = re.findall(r"[a-zäöüß]+", text.lower())
    hits = sum(w in DE_WORDS for w in words)
    return "de" if re.search(r"[äöüß]", text.lower()) or hits >= 3 else "en"


def load() -> list[dict]:
    with DATA.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f]
    for r in rows:
        r["lang"] = language(r["text"])
    return rows


def stdlib_paragraphs() -> list[str]:
    """Benign technical text: every docstring paragraph (40+ chars) in the top-level
    standard library modules of the running Python. Closer to real tool output
    (docs, READMEs) than chat questions, and full of words like "ignore" and "send"."""
    lib = Path(sysconfig.get_paths()["stdlib"])
    out = []
    for f in sorted(lib.glob("*.py")):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node)
                for para in re.split(r"\n\s*\n", doc or ""):
                    para = " ".join(para.split())
                    if len(para) >= 40:
                        out.append(para)
    return out


def metrics(rows: list[dict], key: str) -> dict:
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    tp = sum(r[key] for r in pos)
    fp = sum(r[key] for r in neg)
    return {
        "injections": len(pos), "benign": len(neg),
        "caught": tp, "recall": tp / len(pos) if pos else 0.0,
        "false_positives": fp, "fpr": fp / len(neg) if neg else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
    }


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def run(use_judge: bool) -> dict:
    rows = load()
    judge = judge_from_env() if use_judge else None
    if use_judge and judge is None:
        raise SystemExit("--judge needs MTG_JUDGE=groq|anthropic and the matching API key")
    t0 = time.perf_counter()
    for r in rows:
        d = decide(r["text"], "quarantine", "eval")
        r["action"] = d.action
        r["rules"] = sorted({f.rule for f in d.findings})
        r["blocked"] = d.action == "quarantine"
        r["flagged"] = d.action != "pass"  # quarantined or wrapped
    scan_ms = (time.perf_counter() - t0) * 1000 / len(rows)
    if judge:
        for r in rows:
            r["judge"] = judge.classify(r["text"]).label if not r["blocked"] else "skipped"
            r["blocked_with_judge"] = r["blocked"] or r["judge"] == "injection"

    out = {"source": SOURCE, "rows": len(rows), "scan_ms_per_row": round(scan_ms, 3), "groups": {}}
    test = [r for r in rows if r["split"] == "test"]
    groups = {"all": rows, "train": [r for r in rows if r["split"] == "train"], "test (held out)": test,
              "test, english": [r for r in test if r["lang"] == "en"],
              "test, german": [r for r in test if r["lang"] == "de"]}
    for name, g in groups.items():
        out["groups"][name] = {"blocked": metrics(g, "blocked"), "flagged": metrics(g, "flagged")}
        if judge:
            out["groups"][name]["blocked_with_judge"] = metrics(g, "blocked_with_judge")
    paras = stdlib_paragraphs()
    actions = [decide(p, "quarantine", "eval").action for p in paras]
    out["stdlib_docs"] = {"python": sys.version.split()[0], "paragraphs": len(paras),
                          "blocked": actions.count("quarantine"), "wrapped": actions.count("wrap")}
    rule_counts: dict[str, int] = {}
    for r in rows:
        if r["label"] == 1:
            for rule in r["rules"]:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
    out["rules_on_injections"] = dict(sorted(rule_counts.items(), key=lambda kv: -kv[1]))
    out["false_positive_examples"] = [{"text": r["text"][:160], "rules": r["rules"], "action": r["action"]}
                                      for r in rows if r["split"] == "train" and r["label"] == 0 and r["flagged"]][:10]
    out["missed_examples"] = [r["text"][:160] for r in rows if r["split"] == "train" and r["label"] == 1 and not r["flagged"]][:12]
    out["judge"] = (judge.provider + ":" + judge.model) if judge else None
    return out


def report(res: dict) -> str:
    lines = ["# Injection scanner on a public dataset", "",
             f"Data: {res['source']}, {res['rows']} rows (train + test). Generated by `python -m evals.injection_eval`.",
             "", "\"Blocked\" = the result would be withheld (quarantine). \"Flagged\" = withheld or passed inside "
             "untrusted-data markers (wrap).", "",
             "| Group | Injections | Blocked | Flagged | Benign | False blocks | False flags |",
             "|---|---|---|---|---|---|---|"]
    for name, g in res["groups"].items():
        b, f = g["blocked"], g["flagged"]
        lines.append(f"| {name} | {b['injections']} | {b['caught']} ({pct(b['recall'])}) | "
                     f"{f['caught']} ({pct(f['recall'])}) | {b['benign']} | {b['false_positives']} ({pct(b['fpr'])}) | "
                     f"{f['false_positives']} ({pct(f['fpr'])}) |")
    if res["judge"]:
        lines += ["", f"With LLM judge ({res['judge']}) on what the rules let through:", "",
                  "| Group | Blocked | False blocks |", "|---|---|---|"]
        for name, g in res["groups"].items():
            j = g["blocked_with_judge"]
            lines.append(f"| {name} | {j['caught']}/{j['injections']} ({pct(j['recall'])}) | "
                         f"{j['false_positives']}/{j['benign']} ({pct(j['fpr'])}) |")
    sd = res["stdlib_docs"]
    lines += ["", f"Benign technical text: {sd['paragraphs']} docstring paragraphs from the Python {sd['python']} "
              f"standard library: {sd['blocked']} blocked, {sd['wrapped']} wrapped."]
    lines += ["", f"Scan time: {res['scan_ms_per_row']} ms per row.", "", "Rules that fired on injections: " +
              (", ".join(f"`{k}` {v}" for k, v in res["rules_on_injections"].items()) or "none"), "",
              "## Sample misses (train split only)", ""]
    lines += [f"- {t}" for t in res["missed_examples"]]
    lines += ["", "## False flags (train split only)", ""]
    lines += [f"- {e['action']} ({', '.join(e['rules'])}): {e['text']}" for e in res["false_positive_examples"]] or ["- none"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true")
    args = ap.parse_args()
    res = run(args.judge)
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "injection-eval.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    (ROOT / "results" / "injection-eval.md").write_text(report(res), encoding="utf-8")
    for name, g in res["groups"].items():
        b, f = g["blocked"], g["flagged"]
        print(f"{name:16s} blocked {b['caught']}/{b['injections']} ({pct(b['recall'])})  flagged {f['caught']}/{f['injections']}"
              f"  false blocks {b['false_positives']}/{b['benign']}  false flags {f['false_positives']}/{f['benign']}")
    sd = res["stdlib_docs"]
    print(f"stdlib docs      {sd['paragraphs']} paragraphs: blocked {sd['blocked']}, wrapped {sd['wrapped']}")


if __name__ == "__main__":
    main()
