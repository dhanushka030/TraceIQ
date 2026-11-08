"""NetSentry TraceIQ Flask application."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from io import BytesIO
import hmac, ipaddress, json, logging, threading, time
from types import SimpleNamespace
from flask import Flask, jsonify, render_template, request, send_file, make_response
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
from config import BASIC_AUTH, PUBLIC_MODE, SECRET_KEY, SCAN_TIMEOUT, SCAN_COOLDOWN_SECONDS
from models.store import create_store
from modules.validators import validate_target, resolve_addresses, preferred_address
from modules.scanner import scan_target, nmap_available, nmap_status, scan_engine, NMAP_PATH, NMAP_AVAILABLE
from modules.footprint import collect_footprint
from modules.cve_matcher import match_cves, lookup_cves
from modules.risk_engine import score_exposure
from modules.graph_builder import build_graph
from modules.report_generator import render_report, render_pdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("netsentry")
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, MAX_CONTENT_LENGTH=16_384)
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:*", "http://localhost:*"]}})
store = create_store(app)
log.info("Database backend: %s", store.backend)
# A restart kills in-flight scan threads; don't leave their rows "running" forever.
store.fail_stale()
if NMAP_AVAILABLE: log.info("Nmap available at %s", NMAP_PATH)
else: log.warning("Nmap not found on PATH (NMAP_AVAILABLE=False). Live scans use the built-in TCP scanner.")
_lock = threading.Lock()
_last_scan = 0.0

# ----------------------------------------------------------------- helpers

def assemble_result(target, hosts, footprint, cves, engine, cve_source="none"):
    """Single place that turns raw scan data into the stored/rendered result."""
    risk = score_exposure(hosts, footprint, cves)
    return {"target": target, "engine": engine, "cve_source": cve_source, "hosts": hosts, "footprint": footprint, "cves": cves, "risk": risk, "graph": build_graph(target, hosts, footprint, cves, risk)}

def build_demo(variant="current"):
    """Illustrative sample data (never a live scan), run through the real scoring pipeline.

    "current" is the newer sample; "baseline" is an earlier, less exposed state of the same
    target so the compare view always has a real difference to show.
    """
    port = lambda n, svc, prod="", ver="": {"port": n, "protocol": "tcp", "state": "open", "service": svc, "product": prod, "version": ver}
    ports = [port(22, "ssh", "OpenSSH", "8.2p1"), port(80, "http", "Apache httpd", "2.4.7"), port(9929, "nping-echo"), port(31337, "tcpwrapped")]
    cves = [{"id": "CVE-2021-41773", "cvss": 7.5, "severity": "HIGH", "description": "Offline example match for demonstration only. Verify version applicability.", "matched_product": "Apache httpd 2.4.7", "source": "offline"}]
    if variant == "current":
        ports += [port(21, "ftp", "vsftpd", "2.3.4"), port(3306, "mysql", "MySQL", "5.5.62")]
        cves += [{"id": "CVE-2023-38408", "cvss": 9.8, "severity": "CRITICAL", "description": "Offline example match for demonstration only. Verify OpenSSH agent forwarding applicability.", "matched_product": "OpenSSH 8.2p1", "source": "offline"},
                 {"id": "CVE-2011-2523", "cvss": 9.8, "severity": "CRITICAL", "description": "Offline example match for demonstration only. Historic vsftpd 2.3.4 backdoor; verify the build.", "matched_product": "vsftpd 2.3.4", "source": "offline"}]
    hosts = [{"addresses": ["45.33.32.156"], "hostnames": ["scanme.nmap.org"], "ports": ports}]
    headers = {"strict-transport-security": False, "content-security-policy": False, "x-frame-options": True, "x-content-type-options": variant == "baseline"}
    footprint = {"target": "scanme.nmap.org", "dns": {"A": ["45.33.32.156"], "AAAA": [], "MX": [], "NS": ["ns1.linode.com.", "ns2.linode.com."], "TXT": [], "CNAME": [], "SOA": ["demo sample record"], "spf_present": False, "dmarc_present": False},
                 "whois": {"registrar": "Sample registrar (demo data)", "org": "Nmap Project (demo data)", "creation_date": "demo", "expiration_date": "demo", "country": "US", "name_servers": ["NS1.LINODE.COM", "NS2.LINODE.COM"]},
                 "reverse_dns": [{"ip": "45.33.32.156", "name": "scanme.nmap.org"}], "subdomains": [{"name": "www.scanme.nmap.org", "addresses": ["45.33.32.156"]}],
                 "tls": {"available": False, "trusted": None, "issuer": None, "subject": None, "not_after": None, "days_left": None, "error": "No TLS service reachable (demo data)"},
                 "http": {"status": 200, "url": "http://scanme.nmap.org/", "https": False, "headers": {"Server": "Apache/2.4.7 (Ubuntu)"}, "tech_hints": {"Server": "Apache/2.4.7 (Ubuntu)"}, "security_headers": headers, "admin_paths": []},
                 "errors": [], "notes": ["Demo data is illustrative and is not a current scan."]}
    return assemble_result("scanme.nmap.org", hosts, footprint, cves, "demo", "offline_fallback")

def seed_demo_scans():
    """Idempotently store two sample scans (profile "demo") so history, reports and compare work from a fresh database."""
    existing = store.scans_by_profile("demo")
    if len(existing) >= 2: return [x.id for x in existing[-2:]]
    for x in existing: store.delete_scan(x.id)
    now = datetime.now(timezone.utc); ids = []
    for variant, age in (("baseline", timedelta(days=7)), ("current", timedelta(minutes=1))):
        scan = store.create_scan("scanme.nmap.org", "demo", status="completed", progress="Complete", created_at=now - age, completed_at=now - age, result_json=build_demo(variant))
        ids.append(scan.id)
    return ids

def _json_error(message, status=400): return jsonify({"error": message}), status

def _scan_dict(scan):
    return {"id": scan.id, "target": scan.target, "profile": scan.profile, "status": scan.status, "progress": scan.progress,
            "created_at": scan.created_at.isoformat(), "completed_at": scan.completed_at.isoformat() if scan.completed_at else None, "error": scan.error}

def _get_completed(scan_id):
    """Return (scan, None) or (None, error_response)."""
    scan = store.get_scan(scan_id)
    if not scan: return None, _json_error("Scan not found.", 404)
    if scan.status != "completed": return None, _json_error("Scan results are not ready.", 409)
    return scan, None

def _report_response(html, name, fmt):
    if fmt == "html" or (pdf := render_pdf(html)) is None:
        response = make_response(html); response.headers["Content-Type"] = "text/html; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{name}.html"'
        return response
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name=f"{name}.pdf")

@app.before_request
def require_basic_auth():
    """Optional site-wide password (NETSENTRY_BASIC_AUTH=user:password). /api/health stays open for host health checks."""
    if not BASIC_AUTH or request.path == "/api/health": return None
    auth = request.authorization
    if auth and auth.type == "basic" and hmac.compare_digest(f"{auth.username}:{auth.password}", BASIC_AUTH): return None
    return make_response("Authentication required.", 401, {"WWW-Authenticate": 'Basic realm="NetSentry TraceIQ"'})

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    return response

@app.errorhandler(413)
def too_large(_): return _json_error("Request body is too large.", 413)

@app.errorhandler(Exception)
def unexpected_error(exc):
    if isinstance(exc, HTTPException): return _json_error(exc.description, exc.code or 500)
    log.exception("Unhandled request error")
    if app.testing: return _json_error(str(exc), 500)
    return _json_error("An internal error occurred.", 500)

# ------------------------------------------------------------------ routes

@app.get("/")
def index(): return render_template("index.html", nmap_installed=nmap_available(), engine=scan_engine())

@app.get("/api/health")
def health(): return jsonify({"status": "ok", "engine": scan_engine(), "nmap": nmap_status(), "nmap_path": NMAP_PATH, "database": store.backend, "public_mode": PUBLIC_MODE})

@app.get("/api/demo")
def demo(): return jsonify({"id": "demo", "target": "scanme.nmap.org", "status": "completed", "profile": "demo", "result": build_demo()})

@app.post("/api/demo/seed")
def demo_seed():
    ids = seed_demo_scans()
    return jsonify({"baseline": ids[0], "current": ids[1]})

@app.get("/api/demo/report")
def demo_report():
    fake = SimpleNamespace(id="demo", target="scanme.nmap.org", profile="demo", completed_at=datetime.now(timezone.utc), result_json=build_demo())
    return _report_response(render_report(fake), "netsentry-report-demo", request.args.get("format", "pdf").lower())

@app.post("/api/scan")
def start_scan():
    global _last_scan
    body = request.get_json(silent=True) or {}
    if body.get("authorized") is not True: return _json_error("Confirm that you are authorized to scan this target before starting.")
    try: target = validate_target(body.get("target", ""))
    except ValueError as exc: return _json_error(str(exc))
    profile = body.get("profile", "quick")
    if profile not in ("quick", "standard", "deep"): return _json_error("Profile must be quick, standard, or deep.")
    with _lock:
        now = time.monotonic()
        if now - _last_scan < SCAN_COOLDOWN_SECONDS: return _json_error("Please wait a few seconds before starting another scan.", 429)
        _last_scan = now
    scan_id = store.create_scan(target, profile).id
    threading.Thread(target=_run_scan, args=(scan_id,), daemon=True, name=f"scan-{scan_id}").start()
    return jsonify({"id": scan_id, "status": "queued", "status_url": f"/api/scan/{scan_id}/status"}), 202

def _run_scan(scan_id):
    with app.app_context():
        scan = store.get_scan(scan_id)
        if not scan: return
        def step(progress):
            scan.progress = progress; store.save_scan(scan)
        try:
            scan.status = "running"; step("Collecting footprint")
            footprint = collect_footprint(scan.target)
            engine = scan_engine()
            step("Scanning ports with Nmap" if engine == "nmap" else "Scanning ports (built-in scanner)")
            scan_host = scan.target
            try: ipaddress.ip_address(scan_host)
            except ValueError:
                resolved = resolve_addresses(scan_host)
                if not resolved: raise RuntimeError("The target did not resolve to an address; no scan was run.")
                scan_host = preferred_address(resolved)
            hosts = scan_target(scan_host, scan.profile, SCAN_TIMEOUT)
            step("Matching known vulnerabilities")
            services = [p for h in hosts for p in h.get("ports", [])]
            cves, cve_source = lookup_cves(services, store.cache_adapter())
            step("Scoring exposure")
            scan.result_json = assemble_result(scan.target, hosts, footprint, cves, engine, cve_source)
            scan.status, scan.progress, scan.completed_at = "completed", "Complete", datetime.now(timezone.utc); store.save_scan(scan)
        except Exception as exc:
            log.exception("Scan %s failed", scan_id)
            scan.status, scan.error, scan.progress, scan.completed_at = "failed", str(exc), "Failed", datetime.now(timezone.utc)
            store.save_scan(scan)

@app.get("/api/scan/<int:scan_id>/status")
def scan_status(scan_id):
    scan = store.get_scan(scan_id)
    return jsonify(_scan_dict(scan)) if scan else _json_error("Scan not found.", 404)

@app.get("/api/scan/<int:scan_id>/results")
def scan_results(scan_id):
    scan, err = _get_completed(scan_id)
    return err or jsonify({**_scan_dict(scan), "result": scan.result_json})

@app.get("/api/scan/<int:scan_id>/graph")
def scan_graph(scan_id):
    scan, err = _get_completed(scan_id)
    return err or jsonify(scan.result_json.get("graph", {}))

@app.get("/api/scan/<int:scan_id>/report")
def scan_report(scan_id):
    scan, err = _get_completed(scan_id)
    if err: return err
    fmt = request.args.get("format", "pdf").lower()
    if fmt == "json":
        response = make_response(json.dumps(scan.result_json, indent=2)); response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = f'attachment; filename="netsentry-scan-{scan_id}.json"'
        return response
    return _report_response(render_report(scan), f"netsentry-report-{scan_id}", fmt)

@app.delete("/api/scan/<int:scan_id>")
def delete_scan(scan_id):
    scan = store.get_scan(scan_id)
    if not scan: return _json_error("Scan not found.", 404)
    if scan.status in ("queued", "running"): return _json_error("A running scan cannot be deleted.", 409)
    store.delete_scan(scan_id)
    return jsonify({"deleted": scan_id})

@app.get("/api/history")
def history():
    scans = store.list_scans(200)
    def extra(s):
        risk = (s.result_json or {}).get("risk", {})
        return {"score": risk.get("score"), "label": risk.get("label"), "engine": (s.result_json or {}).get("engine"), "open_ports": sum(len(h.get("ports", [])) for h in (s.result_json or {}).get("hosts", []))}
    return jsonify([_scan_dict(s) | extra(s) for s in scans])

@app.get("/api/compare")
def compare():
    try: a, b = int(request.args["a"]), int(request.args["b"])
    except (KeyError, ValueError): return _json_error("Provide numeric scan IDs a and b.")
    first, second = store.get_scan(a), store.get_scan(b)
    if not first or not second: return _json_error("Both scans must exist.", 404)
    if not first.result_json or not second.result_json: return _json_error("Both scans must be completed.", 409)
    def ports(s): return {(h.get("addresses", [s.target])[0], p["port"], p["protocol"], p.get("service")) for h in s.result_json.get("hosts", []) for p in h.get("ports", [])}
    def titles(s): return {f["title"]: f["severity"] for f in s.result_json.get("risk", {}).get("findings", []) if f.get("severity") != "Info"}
    old, new, t_old, t_new = ports(first), ports(second), titles(first), titles(second)
    score_a, score_b = first.result_json.get("risk", {}).get("score", 0), second.result_json.get("risk", {}).get("score", 0)
    return jsonify({"a": a, "b": b, "target_a": first.target, "target_b": second.target,
                    "new_ports": [list(x) for x in sorted(new - old)], "closed_ports": [list(x) for x in sorted(old - new)],
                    "new_findings": [{"title": t, "severity": s} for t, s in sorted(t_new.items()) if t not in t_old],
                    "resolved_findings": [{"title": t, "severity": s} for t, s in sorted(t_old.items()) if t not in t_new],
                    "score_a": score_a, "score_b": score_b, "score_change": score_b - score_a})

if __name__ == "__main__":
    import os
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False, threaded=True)
