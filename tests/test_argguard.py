import pytest

from mcp_tenant_gate.argguard import check_path, check_url
from mcp_tenant_gate.errors import GateBlocked

ALLOW = ["docs.example.com", "*.acme.example"]


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/admin",
    "http://LOCALHOST./admin",
    "http://127.0.0.1:8080/",
    "http://2130706433/",          # decimal 127.0.0.1
    "http://0x7f000001/",          # hex
    "http://0177.0.0.1/",          # octal
    "http://127.1/",               # short form
    "http://[::1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://10.0.0.5/",
    "http://100.64.0.1/",          # carrier-grade NAT, not global
    "http://0.0.0.0/",
    "http://metadata.google.internal/",
    "http://docs.example.com@evil.example/",
    "file:///etc/passwd",
    "gopher://docs.example.com/",
    "https://evil.example/collect?d=1",
    "https://docs.example.com.evil.example/",
    "https://docs.example.com/\r\nHost: x",
    "https://docs.example.com:99999/",
])
def test_blocked_urls(url):
    with pytest.raises(GateBlocked):
        check_url(url, ALLOW)


@pytest.mark.parametrize("url", [
    "https://docs.example.com/guide?page=2",
    "https://api.acme.example/status",
    "http://eu.api.acme.example/x",
])
def test_allowed_urls(url):
    check_url(url, ALLOW)


def test_wildcard_does_not_match_bare_apex():
    with pytest.raises(GateBlocked):
        check_url("https://acme.example/", ALLOW)


@pytest.mark.parametrize("path", [
    "data/../etc/passwd", "../secrets/prod.env", "/etc/passwd", "C:/Windows/win.ini", "~/.ssh/id_rsa",
    "data\\..\\secrets", "data/%2e%2e/secrets", "data/x\x00.txt", "secrets/prod.env", "datafoo/x", "",
])
def test_blocked_paths(path):
    with pytest.raises(GateBlocked):
        check_path(path, "data")


def test_allowed_path_is_normalised():
    assert check_path("data/./reports//q3.txt", "data") == "data/reports/q3.txt"
