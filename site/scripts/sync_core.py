"""Copy the gateway code into site/engine/core so the Vercel function (whose
root is site/) runs the exact same files as the repo.

    python site/scripts/sync_core.py

tests/test_site_core_in_sync.py fails if the copy drifts from the source.
Only Python sources, the classifier weights and the policy are copied. The
stdio server front (gateway.py) and the optional LLM judge's network code are
copied too, but the site never starts a server or sets a judge key.
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEST = REPO / "site" / "engine" / "core"

PACKAGES = ["mcp_tenant_gate", "upstreams", "attacks"]
FILES = ["tenants.yaml"]


def source_files() -> list[Path]:
    out: list[Path] = []
    for pkg in PACKAGES:
        for p in sorted((REPO / pkg).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".json"):
                out.append(p.relative_to(REPO))
    out += [Path(f) for f in FILES]
    return out


def main() -> None:
    if DEST.exists():
        shutil.rmtree(DEST)
    for rel in source_files():
        target = DEST / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, target)
    print(f"copied {len(source_files())} files to {DEST.relative_to(REPO)}")


if __name__ == "__main__":
    main()
