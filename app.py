"""NetSentry TraceIQ Flask application."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import logging, threading, time
from flask import Flask, jsonify, render_template, request, send_file, make_response
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
from io import BytesIO
from config import BASE_DIR, DATABASE_URL, SECRET_KEY, SCAN_TIMEOUT, SCAN_COOLDOWN_SECONDS
from models.db import db, Scan, cve_cache_adapter
from modules.validators import validate_target, resolve_addresses
from modules.scanner import scan_target, nmap_available
from modules.footprint import collect_footprint
from modules.cve_matcher import match_cves
from modules.risk_engine import score_exposure
from modules.graph_builder import build_graph
from modules.report_generator import render_report, render_pdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("netsentry")
app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, SQLALCHEMY_DATABASE_URI=DATABASE_URL, SQLALCHEMY_TRACK_MODIFICATIONS=False, MAX_CONTENT_LENGTH=16_384)
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:*", "http://localhost:*"]}})
db.init_app(app)
with app.app_context(): db.create_all()
_lock = threading.Lock()
_last_scan = 0.0
DEMO_RESULT = {"target":"scanme.nmap.org","hosts":[{"addresses":["45.33.32.156"],"hostnames":["scanme.nmap.org"],"ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"8.2p1"},{"port":80,"protocol":"tcp","state":"open","service":"http","product":"Apache httpd","version":"2.4.7"}]}],"footprint":{"dns":{"A":["45.33.32.156"],"NS":["ns1.linode.com."],"spf_present":False,"dmarc_present":False},"whois":{"registrar":"Demo data"},"http":{"https":False,"security_headers":{"strict-transport-security":False,"content-security-policy":False,"x-frame-options":True,"x-content-type-options":False},"admin_paths":[]},"reverse_dns":[]},"cves":[{"id":"CVE-2021-41773","cvss":7.5,"severity":"HIGH","description":"Offline example match for demonstration only. Verify version applicability."}],"risk":{"score":48,"label":"Medium","findings":[{"severity":"High","type":"cve","title":"CVE-2021-41773 (demo example)","detail":"Offline illustrative CVE match; applicability is not confirmed.","remediation":"Verify installed version and apply vendor guidance."}],"why":["Demo data is illustrative and is not a current scan."]}}

def _json_error(message, status=400): return jsonify({"error": message}), status
def _scan_dict(scan):
    return {"id":scan.id,"target":scan.target,"profile":scan.profile,"status":scan.status,"progress":scan.progress,"created_at":scan.created_at.isoformat(),"completed_at":scan.completed_at.isoformat() if scan.completed_at else None,"error":scan.error}

@app.errorhandler(413)
def too_large(_): return _json_error("Request body is too large.", 413)

@app.errorhandler(Exception)
def unexpected_error(exc):
    if isinstance(exc, HTTPException): return _json_error(exc.description, exc.code or 500)
    log.exception("Unhandled request error")
    if app.testing: return _json_error(str(exc), 500)
    return _json_error("An internal error occurred.", 500)

@app.get("/")
def index(): return render_template("index.html", nmap_installed=nmap_available())

@app.get("/api/demo")
def demo(): return jsonify({"id":"demo","target":DEMO_RESULT["target"],"status":"completed","profile":"demo","result":DEMO_RESULT})

@app.post("/api/scan")
def start_scan():
    global _last_scan
    body=request.get_json(silent=True) or {}
    if body.get("authorized") is not True: return _json_error("Confirm that you are authorized to scan this target before starting.")
    try: target=validate_target(body.get("target", ""))
    except ValueError as exc: return _json_error(str(exc))
    profile=body.get("profile", "quick")
    if profile not in ("quick","standard","deep"): return _json_error("Profile must be quick, standard, or deep.")
    with _lock:
        now=time.monotonic()
        if now-_last_scan < SCAN_COOLDOWN_SECONDS: return _json_error("Please wait before starting another scan.", 429)
        _last_scan=now
    with app.app_context():
        scan=Scan(target=target,profile=profile); db.session.add(scan); db.session.commit(); scan_id=scan.id
    threading.Thread(target=_run_scan,args=(scan_id,),daemon=True,name=f"scan-{scan_id}").start()
    return jsonify({"id":scan_id,"status":"queued","status_url":f"/api/scan/{scan_id}/status"}),202

def _run_scan(scan_id):
    with app.app_context():
        scan=Scan.query.get(scan_id)
        if not scan: return
        try:
            scan.status,scan.progress="running","Collecting footprint"; db.session.commit()
            footprint=collect_footprint(scan.target)
            scan.progress="Running Nmap"; db.session.commit()
            scan_host=scan.target
            try:
                import ipaddress
                ipaddress.ip_address(scan_host)
            except ValueError:
                resolved=resolve_addresses(scan_host)
                if not resolved: raise RuntimeError("The target did not resolve to an address; no scan was run.")
                scan_host=resolved[0]
            hosts=scan_target(scan_host,scan.profile,SCAN_TIMEOUT)
            scan.progress="Matching known vulnerabilities"; db.session.commit()
            services=[p for h in hosts for p in h.get("ports",[])]
            cves=match_cves(services,cve_cache_adapter())
            risk=score_exposure(hosts,footprint,cves)
            scan.result_json={"target":scan.target,"hosts":hosts,"footprint":footprint,"cves":cves,"risk":risk,"graph":build_graph(scan.target,hosts,footprint,cves,risk)}
            scan.status,scan.progress,scan.completed_at="completed","Complete",datetime.now(timezone.utc); db.session.commit()
        except Exception as exc:
            log.exception("Scan %s failed",scan_id); scan.status,scan.error,scan.progress="failed",str(exc),"Failed"; scan.completed_at=datetime.now(timezone.utc); db.session.commit()

@app.get("/api/scan/<int:scan_id>/status")
def scan_status(scan_id):
    scan=db.session.get(Scan,scan_id)
    if not scan:return _json_error("Scan not found.",404)
    return jsonify(_scan_dict(scan))

@app.get("/api/scan/<int:scan_id>/results")
def scan_results(scan_id):
    scan=db.session.get(Scan,scan_id)
    if not scan:return _json_error("Scan not found.",404)
    if scan.status!="completed":return _json_error("Scan results are not ready.",409)
    return jsonify({**_scan_dict(scan),"result":scan.result_json})

@app.get("/api/scan/<int:scan_id>/graph")
def scan_graph(scan_id):
    scan=db.session.get(Scan,scan_id)
    if not scan:return _json_error("Scan not found.",404)
    if scan.status!="completed":return _json_error("Scan results are not ready.",409)
    return jsonify(scan.result_json.get("graph",{}))

@app.get("/api/scan/<int:scan_id>/report")
def scan_report(scan_id):
    scan=db.session.get(Scan,scan_id)
    if not scan:return _json_error("Scan not found.",404)
    if scan.status!="completed":return _json_error("Scan results are not ready.",409)
    html=render_report(scan)
    if request.args.get("format", "pdf").lower()=="html":
        response=make_response(html); response.headers["Content-Type"]="text/html; charset=utf-8"; response.headers["Content-Disposition"]=f'attachment; filename="netsentry-report-{scan_id}.html"'; return response
    pdf=render_pdf(html)
    if pdf is None:
        response=make_response(html); response.headers["Content-Type"]="text/html; charset=utf-8"; response.headers["Content-Disposition"]=f'attachment; filename="netsentry-report-{scan_id}.html"'; return response
    return send_file(BytesIO(pdf),mimetype="application/pdf",as_attachment=True,download_name=f"netsentry-report-{scan_id}.pdf")

@app.get("/api/history")
def history():
    scans=Scan.query.order_by(Scan.created_at.desc()).limit(200).all()
    return jsonify([_scan_dict(s) | ({"score":s.result_json.get("risk",{}).get("score"),"label":s.result_json.get("risk",{}).get("label")} if s.result_json else {}) for s in scans])

@app.get("/api/compare")
def compare():
    try:a,b=int(request.args["a"]),int(request.args["b"])
    except (KeyError,ValueError):return _json_error("Provide numeric scan IDs a and b.")
    first,second=db.session.get(Scan,a),db.session.get(Scan,b)
    if not first or not second:return _json_error("Both scans must exist.",404)
    if not first.result_json or not second.result_json:return _json_error("Both scans must be completed.",409)
    def ports(s):return {(h.get("addresses",[s.target])[0],p["port"],p["protocol"],p.get("service")) for h in s.result_json.get("hosts",[]) for p in h.get("ports",[])}
    old,new=ports(first),ports(second)
    return jsonify({"a":a,"b":b,"new_ports":[list(x) for x in sorted(new-old)],"closed_ports":[list(x) for x in sorted(old-new)],"score_a":first.result_json.get("risk",{}).get("score",0),"score_b":second.result_json.get("risk",{}).get("score",0),"score_change":second.result_json.get("risk",{}).get("score",0)-first.result_json.get("risk",{}).get("score",0)})

if __name__=="__main__":
    if not nmap_available(): log.warning("Nmap is not installed or not on PATH. Live scans are unavailable; Demo Mode remains available.")
    app.run(host="127.0.0.1",port=5000,debug=False,threaded=True)
