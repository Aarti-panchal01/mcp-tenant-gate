"""Write site/data/recorded.json: numbers the page shows that are not computed live.

    python site/scripts/record.py

- attack suite: runs the real suite in-process now (same as the "Run live" button)
- held-out eval: read from results/injection-layers.json and results/injection-eval.json,
  which `python -m evals.compare_layers` and `python -m evals.injection_eval` wrote
- error analysis: the hand-made grouping from ERROR-ANALYSIS.md
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "site"))

from engine import playground  # noqa: E402


def main() -> None:
    suite = playground.run_suite()
    layers = json.loads((REPO / "results" / "injection-layers.json").read_text(encoding="utf-8"))
    evalj = json.loads((REPO / "results" / "injection-eval.json").read_text(encoding="utf-8"))
    out = {
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "suite": suite,
        "layers": layers,
        "eval_source": evalj.get("source"),
        "error_analysis": {
            "misses": 33, "wrapped": 19, "passed": 14,
            "categories": [
                ["Role play and hypothetical framing", 8, 6, 2,
                 "Least privilege and output policy. The text reads like a normal creative request."],
                ["Ordinary looking task requests", 6, 3, 3,
                 "Tool scoping and argument checks. If the tenant has no SQL tool, the request does nothing."],
                ["Prompt extraction", 5, 3, 2, "Keep secrets out of the prompt. Not a wording problem."],
                ["Misspelling and typo tricks", 4, 1, 3,
                 "Better normalisation or a fuzzy matcher. The one group a detector change could help."],
                ["Pushy answer coercion", 4, 4, 0, "Already wrapped. Tool output provenance is the proper fix."],
                ["Language switch trigger strings", 3, 0, 3, "Nothing wording based. Output schema checks."],
                ["Harmless probes", 3, 3, 0, "Probes, not harmful alone. Rate limits and audit logs."],
            ],
            "cross_cuts": [
                "10 of the 33 are a normal question with the injection stuck on the end.",
                "9 of the 33 carry the payload in German or Spanish.",
                "19 of the 33 were still wrapped as untrusted data. 14 got through with nothing.",
            ],
        },
    }
    dest = REPO / "site" / "data" / "recorded.json"
    dest.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {dest.relative_to(REPO)}: suite {suite['blocked']}/{suite['attacks']}")


if __name__ == "__main__":
    main()
