import json

import pytest

from mcp_tenant_gate.audit import AuditLog, record_hash, verify_file, verify_lines


def _log(tmp_path, n=5):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, clock=lambda: 1.0)
    for i in range(n):
        log.append("call", i=i)
    return path, log


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_clean_chain_verifies(tmp_path):
    path, log = _log(tmp_path)
    r = verify_file(path, expected_head=log.head())
    assert r.ok and r.records == 5


def test_edited_record_detected(tmp_path):
    path, _ = _log(tmp_path)
    lines = _lines(path)
    rec = json.loads(lines[2])
    rec["i"] = 99
    lines[2] = json.dumps(rec, sort_keys=True)
    r = verify_lines(lines)
    assert not r.ok and r.bad_line == 3 and "edited" in r.reason


def test_rehashed_edit_still_breaks_next_link(tmp_path):
    path, _ = _log(tmp_path)
    lines = _lines(path)
    rec = json.loads(lines[2])
    rec["i"] = 99
    rec["hash"] = record_hash(rec)
    lines[2] = json.dumps(rec, sort_keys=True)
    r = verify_lines(lines)
    assert not r.ok and r.bad_line == 4


@pytest.mark.parametrize("op", ["delete", "swap", "duplicate"])
def test_deleted_reordered_inserted_detected(tmp_path, op):
    path, _ = _log(tmp_path)
    lines = _lines(path)
    if op == "delete":
        del lines[1]
    elif op == "swap":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines.insert(2, lines[1])
    assert not verify_lines(lines).ok


def test_truncated_tail_needs_an_anchored_head(tmp_path):
    path, log = _log(tmp_path)
    head = log.head()
    lines = _lines(path)[:-2]
    assert verify_lines(lines).ok  # a chopped tail looks fine on its own...
    assert not verify_lines(lines, expected_head=head).ok  # ...but not against the anchored head


def test_reopen_continues_chain_and_refuses_broken_file(tmp_path):
    path, _ = _log(tmp_path, 2)
    AuditLog(path).append("call", i=2)
    r = verify_file(path)
    assert r.ok and r.records == 3
    lines = _lines(path)
    rec = json.loads(lines[1])
    rec["i"] = 7
    lines[1] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="broken audit log"):
        AuditLog(path)
