import time
import app as netsentry

def _fake_scan(monkeypatch, ports=None):
    ports = ports if ports is not None else [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "product": "", "version": ""}]
    monkeypatch.setattr(netsentry, "collect_footprint", lambda t: {"dns": {}, "http": {"headers": {}, "security_headers": {}, "admin_paths": []}, "tls": {}})
    monkeypatch.setattr(netsentry, "scan_target", lambda host, profile, timeout: [{"addresses": [host], "hostnames": [], "ports": ports}])
    monkeypatch.setattr(netsentry, "match_cves", lambda services, cache=None: [])

def _run(client, target="127.0.0.1"):
    netsentry._last_scan = 0.0
    r = client.post("/api/scan", json={"target": target, "profile": "quick", "authorized": True})
    assert r.status_code == 202, r.json
    sid = r.json["id"]
    for _ in range(100):
        status = client.get(f"/api/scan/{sid}/status").json
        if status["status"] in ("completed", "failed"): return sid, status
        time.sleep(0.05)
    raise AssertionError("scan did not finish")

def test_requires_authorization(client):
    r = client.post("/api/scan", json={"target": "127.0.0.1"})
    assert r.status_code == 400 and "authorized" in r.json["error"]

def test_rejects_out_of_scope_target(client):
    r = client.post("/api/scan", json={"target": "8.8.8.8", "authorized": True})
    assert r.status_code == 400 and "scope" in r.json["error"]

def test_rejects_bad_profile(client):
    r = client.post("/api/scan", json={"target": "127.0.0.1", "authorized": True, "profile": "insane"})
    assert r.status_code == 400

def test_cooldown_returns_429(client, monkeypatch):
    _fake_scan(monkeypatch)
    _run(client)
    r = client.post("/api/scan", json={"target": "127.0.0.1", "authorized": True})
    assert r.status_code == 429

def test_full_scan_lifecycle(client, monkeypatch):
    _fake_scan(monkeypatch)
    sid, status = _run(client)
    assert status["status"] == "completed"
    res = client.get(f"/api/scan/{sid}/results").json["result"]
    assert res["risk"]["score"] >= 20 and res["graph"]["nodes"]
    assert client.get(f"/api/scan/{sid}/graph").json["nodes"]
    assert any(h["id"] == sid and h["score"] == res["risk"]["score"] for h in client.get("/api/history").json)
    assert client.get(f"/api/scan/{sid}/report?format=html").mimetype == "text/html"
    assert client.get(f"/api/scan/{sid}/report?format=json").json["target"] == "127.0.0.1"
    assert client.delete(f"/api/scan/{sid}").json == {"deleted": sid}
    assert client.get(f"/api/scan/{sid}/status").status_code == 404

def test_failed_scan_records_error(client, monkeypatch):
    _fake_scan(monkeypatch)
    def boom(*a, **k): raise RuntimeError("engine exploded")
    monkeypatch.setattr(netsentry, "scan_target", boom)
    sid, status = _run(client)
    assert status["status"] == "failed" and "engine exploded" in status["error"]
    assert client.get(f"/api/scan/{sid}/results").status_code == 409

def test_compare_reports_new_and_closed_ports(client, monkeypatch):
    _fake_scan(monkeypatch, [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "", "version": ""}])
    a, _ = _run(client)
    _fake_scan(monkeypatch, [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "product": "", "version": ""}])
    b, _ = _run(client)
    diff = client.get(f"/api/compare?a={a}&b={b}").json
    assert [p[1] for p in diff["new_ports"]] == [23] and [p[1] for p in diff["closed_ports"]] == [22]
    assert diff["score_change"] > 0 and diff["new_findings"]

def test_compare_validates_input(client):
    assert client.get("/api/compare?a=x&b=1").status_code == 400
    assert client.get("/api/compare?a=998&b=999").status_code == 404

def test_demo_and_demo_report(client):
    demo = client.get("/api/demo").json["result"]
    assert demo["engine"] == "demo" and demo["graph"]["nodes"] and demo["risk"]["breakdown"]
    r = client.get("/api/demo/report?format=html")
    assert r.status_code == 200 and b"SAMPLE DATA" in r.data

def test_security_headers_and_health(client):
    r = client.get("/api/health")
    assert r.json["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff" and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]

def test_index_renders_without_external_assets(client):
    html = client.get("/").get_data(as_text=True)
    assert "cdn." not in html and "unpkg" not in html and "googleapis" not in html
