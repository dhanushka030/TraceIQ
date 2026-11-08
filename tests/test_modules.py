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
    def __init__(self, payload): self.payload = payload
    def raise_for_status(self): pass
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
