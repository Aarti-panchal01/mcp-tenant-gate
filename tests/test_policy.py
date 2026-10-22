import copy

import pytest
import yaml

from conftest import ACME, GLOBEX, ROOT
from mcp_tenant_gate.errors import GateBlocked
from mcp_tenant_gate.policy import PolicyError, hash_key, parse_policy

BASE = yaml.safe_load((ROOT / "tenants.yaml").read_text(encoding="utf-8"))


def mutate(fn):
    data = copy.deepcopy(BASE)
    fn(data)
    return data


def test_demo_policy_loads(policy):
    assert set(policy.tenants) == {"acme", "globex"}
    assert policy.tenants["globex"].pii_mode == "block"


def test_authenticate_known_and_unknown(policy):
    assert policy.authenticate(ACME).tenant_id == "acme"
    assert policy.authenticate(GLOBEX).tenant_id == "globex"
    for bad in (None, "", "acme", ACME + " "):
        with pytest.raises(GateBlocked) as e:
            policy.authenticate(bad)
        assert e.value.layer == "auth"


def test_keys_stored_only_as_hashes():
    text = (ROOT / "tenants.yaml").read_text(encoding="utf-8")
    assert hash_key(ACME) in text
    # the plain demo key is only in a comment, never used as a value
    assert f"api_key_sha256: {ACME}" not in text


@pytest.mark.parametrize("fn,msg", [
    (lambda d: d["tenants"]["acme"].update(api_key_sha256="abc"), "64 lowercase hex"),
    (lambda d: d["tenants"]["globex"].update(api_key_sha256=d["tenants"]["acme"]["api_key_sha256"]), "duplicate"),
    (lambda d: d["tenants"]["globex"]["upstreams"].append("nope"), "unknown upstream"),
    (lambda d: d["tenants"]["globex"]["tools"].update({"evil__lookup": {}}), "cannot use"),
    (lambda d: d["tenants"]["acme"]["tools"]["notes__read_note"]["args"]["note_id"].update(pattern="("), "bad regex"),
    (lambda d: d["tenants"]["acme"]["tools"]["notes__search_notes"].update(schema={"type": 5}), "bad JSON schema"),
    (lambda d: d["tenants"]["acme"].update(pii=["ssn"]), "unknown pii"),
    (lambda d: d["tenants"]["acme"].update(pii_mode="log"), "pii_mode"),
    (lambda d: d["upstreams"].update({"bad_name": {"command": "x"}}), "lowercase letters"),
    (lambda d: d["tenants"]["acme"]["tools"]["notes__read_note"]["args"]["note_id"].update(typo=1), "unknown keys"),
    (lambda d: d["tenants"]["acme"]["tools"].update({"readnote": {}}), "namespaced"),
    (lambda d: d["tenants"]["acme"]["tools"]["notes__read_file"]["args"]["path"].update(kind="file"), "bad kind"),
])
def test_bad_policies_fail_closed(fn, msg):
    with pytest.raises(PolicyError, match=msg):
        parse_policy(mutate(fn))


def test_exact_rule_beats_wildcard(policy):
    acme = policy.tenants["acme"]
    assert acme.tool_rule("evil__send_report").pattern == "evil__send_report"
    assert acme.tool_rule("evil__lookup").pattern == "evil__*"
    assert acme.tool_rule("notes__delete_everything") is None


def test_arg_rules(policy):
    acme = policy.tenants["acme"]
    policy.check_args(acme, "notes__read_note", {"note_id": "note-0123456789ab"})
    with pytest.raises(GateBlocked, match="fails pattern"):
        policy.check_args(acme, "notes__read_note", {"note_id": "../../note"})
    with pytest.raises(GateBlocked, match="must be a string"):
        policy.check_args(acme, "notes__read_note", {"note_id": 7})
    with pytest.raises(GateBlocked, match="too long"):
        policy.check_args(acme, "notes__create_note", {"title": "x" * 201, "body": ""})
    with pytest.raises(GateBlocked, match="schema"):
        policy.check_args(acme, "notes__search_notes", {"query": "a"})
    with pytest.raises(GateBlocked, match="not available"):
        policy.check_args(policy.tenants["globex"], "notes__fetch_url", {"url": "https://docs.example.com"})
