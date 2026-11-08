import socket, threading
import requests
from modules import cve_matcher, footprint, graph_builder, scanner
from modules.risk_engine import score_exposure, risk_label

# ---- built-in scanner
def _serve(banner: bytes):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    def run():
        while True:
            try: conn, _ = srv.accept()
            except OSError: return
            try: conn.sendall(banner)
            finally: conn.close()
    threading.Thread(target=run, daemon=True).start()
    return srv

def test_probe_port_reads_ssh_banner():
    srv = _serve(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")
    try:
        found = scanner._probe_port("127.0.0.1", srv.getsockname()[1], 1.0, True)
    finally: srv.close()
    assert found["state"] == "open" and found["product"] == "OpenSSH" and found["version"] == "8.2p1"

def test_probe_port_closed_returns_none():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert scanner._probe_port("127.0.0.1", port, 0.3, False) is None

def test_connect_scan_finds_listener(monkeypatch):
    srv = _serve(b"")
    port = srv.getsockname()[1]
    monkeypatch.setattr(scanner, "QUICK_PORTS", (port,))
    try: hosts = scanner.connect_scan("127.0.0.1", "quick")
    finally: srv.close()
    assert [p["port"] for p in hosts[0]["ports"]] == [port]

def test_parse_banner_variants():
    assert scanner.parse_banner(80, "Apache/2.4.7 (Ubuntu)")["product"] == "Apache httpd"
    assert scanner.parse_banner(80, "nginx/1.18.0")["version"] == "1.18.0"
    assert scanner.parse_banner(21, "220 (vsFTPd 3.0.3)")["product"].lower() == "vsftpd"
    assert scanner.parse_banner(3306, "")["service"] == "mysql"

def test_scan_target_uses_builtin_without_nmap(monkeypatch):
    monkeypatch.setattr(scanner, "nmap_available", lambda: False)
    monkeypatch.setattr(scanner, "connect_scan", lambda host, profile: [{"addresses": [host], "hostnames": [], "ports": []}])
    assert scanner.scan_engine() == "builtin"
    assert scanner.scan_target("127.0.0.1", "quick")[0]["addresses"] == ["127.0.0.1"]

# ---- CVE matcher
class _Resp:
    def __init__(self, payload, status=200): self.payload, self.status_code = payload, status
    def raise_for_status(self):
        if self.status_code >= 400: raise requests.HTTPError(f"HTTP {self.status_code}")
    def json(self): return self.payload

NVD = {"vulnerabilities": [{"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "d"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}

def test_nvd_results_are_cached_and_parsed(monkeypatch):
    monkeypatch.setattr(cve_matcher.requests, "get", lambda *a, **k: _Resp(NVD))
    cache = {}
    out = cve_matcher.match_cves([{"product": "Apache httpd", "version": "2.4.7"}], cache)
    assert out[0]["id"] == "CVE-1" and out[0]["source"] == "nvd" and cache

def test_offline_fallback_is_not_cached(monkeypatch):
    def down(*a, **k): raise requests.ConnectionError()
    monkeypatch.setattr(cve_matcher.requests, "get", down)
    cache = {}
    out = cve_matcher.match_cves([{"product": "Apache httpd", "version": "2.4.7"}], cache)
    assert out and out[0]["source"] == "offline" and cache == {}

def test_services_without_product_are_skipped(monkeypatch):
    monkeypatch.setattr(cve_matcher.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no lookup expected")))
    assert cve_matcher.match_cves([{"service": "http"}]) == []

# ---- risk engine
def test_breakdown_and_labels():
    result = score_exposure([{"ports": [{"port": 445}]}])
    assert result["breakdown"]["Exposed services"] == 18 and result["risky_ports"] == [445]
    assert [risk_label(s) for s in (0, 25, 50, 75)] == ["Low", "Medium", "High", "Critical"]

def test_no_web_server_does_not_trigger_https_finding():
    result = score_exposure([], {"http": {"headers": {}, "security_headers": {}, "admin_paths": []}})
    assert result["score"] == 0

def test_tls_and_email_findings():
    fp = {"tls": {"available": True, "trusted": False, "days_left": -1, "error": "expired"}, "dns": {"spf_present": False, "dmarc_present": False}}
    types = {f["type"] for f in score_exposure([], fp)["findings"]}
    assert {"tls_expired", "missing_spf", "missing_dmarc"} <= types

# ---- graph
def test_graph_links_cves_to_matching_service():
    hosts = [{"addresses": ["10.0.0.1"], "ports": [{"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.7"}]}]
    graph = graph_builder.build_graph("10.0.0.1", hosts, {"dns": {"A": ["10.0.0.1"]}}, [{"id": "CVE-1", "severity": "HIGH", "matched_product": "Apache httpd 2.4.7"}], {"label": "High"})
    kinds = {n["kind"] for n in graph["nodes"]}
    assert kinds == {"target", "host", "service", "cve", "dns"}
    cve = next(n for n in graph["nodes"] if n["kind"] == "cve")
    svc = next(n for n in graph["nodes"] if n["kind"] == "service")
    assert {"from": svc["id"], "to": cve["id"]} in graph["edges"]

# ---- footprint
def test_footprint_skips_dns_and_whois_for_private_ip(monkeypatch):
    monkeypatch.setattr(footprint, "collect_tls", lambda h: {"available": False})
    monkeypatch.setattr(footprint, "collect_http", lambda t: {"headers": {}, "security_headers": {}, "admin_paths": []})
    data = footprint.collect_footprint("127.0.0.1")
    assert data["dns"] == {} and data["whois"] == {} and data["notes"]

def test_collect_tls_reports_unreachable():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    info = footprint.collect_tls("127.0.0.1", port)
    assert info["available"] is False and info["error"]

# ---- hardening: NVD 429 / timeouts, WHOIS failure, fake Nmap binary
def test_nvd_429_waits_then_retries_once(monkeypatch):
    calls, sleeps = [], []
    def fake_get(*a, **k):
        calls.append(1); return _Resp({}, 429) if len(calls) == 1 else _Resp(NVD)
    monkeypatch.setattr(cve_matcher.requests, "get", fake_get)
    monkeypatch.setattr(cve_matcher.time, "sleep", sleeps.append)
    out, source = cve_matcher.lookup_cves([{"product": "Apache httpd", "version": "2.4.7"}], {})
    assert len(calls) == 2 and sleeps == [cve_matcher.RATE_LIMIT_WAIT] and source == "nvd" and out[0]["id"] == "CVE-1"

def test_nvd_persistent_429_falls_back_offline(monkeypatch):
    monkeypatch.setattr(cve_matcher.requests, "get", lambda *a, **k: _Resp({}, 429))
    monkeypatch.setattr(cve_matcher.time, "sleep", lambda s: None)
    cache = {}
    out, source = cve_matcher.lookup_cves([{"product": "Apache httpd", "version": "2.4.7"}], cache)
    assert source == "offline_fallback" and out and out[0]["source"] == "offline" and cache == {}

def test_nvd_timeout_falls_back_offline(monkeypatch):
    def slow(*a, **k): raise requests.Timeout()
    monkeypatch.setattr(cve_matcher.requests, "get", slow)
    assert cve_matcher.lookup_cves([{"product": "OpenSSH", "version": "8.2p1"}])[1] == "offline_fallback"

def test_whois_failure_is_reported_not_raised(monkeypatch):
    def boom(t): raise RuntimeError("whois server refused")
    for name, value in (("collect_dns", lambda t: {"spf_present": True, "dmarc_present": True}), ("collect_whois", boom), ("find_subdomains", lambda t: []), ("collect_tls", lambda h: {"available": False}), ("collect_http", lambda t: {"headers": {}, "security_headers": {}, "admin_paths": []})):
        monkeypatch.setattr(footprint, name, value)
    data = footprint.collect_footprint("example.org")
    assert data["whois"] is None and "refused" in data["whois_error"] and data["dns"]["spf_present"]

def test_scan_runs_real_subprocess_through_fake_nmap(monkeypatch, tmp_path):
    import os, sys
    xml = '<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port></ports></host></nmaprun>'
    script = tmp_path / "fake_nmap.py"
    script.write_text("import sys\nassert '-oX' in sys.argv\nprint(" + repr(xml) + ")\n")
    launcher = tmp_path / ("nmap.bat" if os.name == "nt" else "nmap")
    if os.name == "nt": launcher.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n')
    else: launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    launcher.chmod(0o755)
    monkeypatch.setattr(scanner, "NMAP_PATH", str(launcher)); monkeypatch.setattr(scanner, "NMAP_AVAILABLE", True)
    hosts = scanner.scan_target("127.0.0.1", "standard", 30)
    assert hosts[0]["ports"][0]["product"] == "OpenSSH" and scanner.scan_engine() == "nmap"
    monkeypatch.setattr(scanner, "NMAP_AVAILABLE", False)
    assert scanner.scan_engine() == "builtin" and scanner.nmap_status().startswith("not_installed")

def test_preferred_address_picks_ipv4_over_sorted_ipv6():
    from modules.validators import preferred_address
    assert preferred_address(sorted(["2600:3c01::f03c:91ff:fe18:bb2f", "45.33.32.156"])) == "45.33.32.156"
    assert preferred_address(["2600:3c01::1"]) == "2600:3c01::1"

def test_nmap_gets_dash_6_only_for_ipv6(monkeypatch):
    seen = []
    class R: returncode, stdout, stderr = 0, "<nmaprun></nmaprun>", ""
    monkeypatch.setattr(scanner.subprocess, "run", lambda cmd, **k: seen.append(cmd) or R())
    scanner._run_nmap("2600:3c01::1", "quick", 30); scanner._run_nmap("45.33.32.156", "quick", 30)
    assert "-6" in seen[0] and "-6" not in seen[1]
