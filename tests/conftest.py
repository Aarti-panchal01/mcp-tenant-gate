import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp_tenant_gate.policy import load_policy  # noqa: E402

ACME = "acme-demo-key-7f3a"
GLOBEX = "globex-demo-key-91c2"


@pytest.fixture
def policy():
    return load_policy(ROOT / "tenants.yaml")
