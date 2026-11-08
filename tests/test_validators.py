import json
import pytest
from modules.validators import normalize_target, validate_target, is_allowed_target

def test_normalize_domain_and_ip():
    assert normalize_target("SCANME.NMAP.ORG.") == "scanme.nmap.org"
    assert normalize_target("127.0.0.1") == "127.0.0.1"

@pytest.mark.parametrize("value", ["", "https://scanme.nmap.org", "example.com;whoami", "bad host", "-bad.example"])
def test_rejects_malformed_or_url(value):
    with pytest.raises(ValueError): normalize_target(value)

@pytest.mark.parametrize("value", ["127.0.0.1", "10.2.3.4", "172.16.1.1", "192.168.1.2", "scanme.nmap.org"])
def test_allowed_targets(value):
    assert validate_target(value) == value

def test_public_target_requires_explicit_allowlist(tmp_path):
    allow = tmp_path / "allowed.json"; allow.write_text(json.dumps(["example.com"]))
    assert validate_target("example.com", allow) == "example.com"
    with pytest.raises(ValueError): validate_target("other.example", allow)

def test_private_hostname_only_when_every_address_is_private(tmp_path):
    allow=tmp_path/"allow.json";allow.write_text("[]")
    assert is_allowed_target("lan.example",allow,lambda _: ["10.0.0.2"])
    assert not is_allowed_target("lan.example",allow,lambda _: ["10.0.0.2","8.8.8.8"])
