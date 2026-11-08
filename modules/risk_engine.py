"""Explainable exposure scoring."""
from __future__ import annotations
from config import RISK_WEIGHTS

def score_exposure(hosts: list[dict], footprint: dict | None = None, cves: list[dict] | None = None, weights: dict | None = None) -> dict:
    weights = weights or RISK_WEIGHTS
    findings = []
    points = 0
    for host in hosts:
        for port in host.get("ports", []):
            value = weights.get("port", {}).get(str(port.get("port")), 0)
            if value:
                points += value
                service_name = str(port.get("service", "service")).replace("_", " ").title()
                findings.append({"severity": "High" if value >= 12 else "Medium", "type": "risky_port", "title": f"Potentially risky service on port {port.get('port')}", "detail": f"{service_name} is reachable on port {port.get('port')}.", "remediation": "Close the port if unused; restrict it to trusted networks and require strong authentication."})
            if port.get("product") and port.get("version"):
                findings.append({"severity": "Info", "type": "version_disclosure", "title": f"Version identified: {port['product']} {port['version']}", "detail": "Service version information was returned by the target.", "remediation": "Keep the service patched and avoid exposing version banners where possible."})
    matched_products = {str(c.get("matched_product", "")).lower().split()[0] for c in cves or [] if c.get("matched_product")}
    counted_versions = set()
    for host in hosts:
        for port in host.get("ports", []):
            product = str(port.get("product", "")); version = str(port.get("version", ""))
            if product and version and any(token in product.lower() for token in matched_products) and (product, version) not in counted_versions:
                counted_versions.add((product, version)); value = weights.get("outdated_version", 12); points += value
                findings.append({"severity": "Medium", "type": "outdated_version", "title": f"Review detected version: {product} {version}", "detail": "A CVE keyword match references this product; confirm whether the detected version is affected before treating it as vulnerable.", "remediation": "Check the vendor advisory and upgrade or apply the supported mitigation if this version is affected."})
    fp = footprint or {}
    http = fp.get("http", {})
    for header, present in http.get("security_headers", {}).items():
        if not present:
            points += weights.get("missing_security_header", 4)
            findings.append({"severity": "Low", "type": "missing_header", "title": f"Missing {header}", "detail": "A recommended browser security response header was not detected.", "remediation": "Configure the web server to return this security header."})
    if http and not http.get("https", False):
        points += weights.get("no_https", 8)
        findings.append({"severity": "Medium", "type": "no_https", "title": "HTTPS not confirmed", "detail": "No successful HTTPS response was confirmed.", "remediation": "Enable HTTPS with a valid certificate and redirect HTTP traffic."})
    for panel in http.get("admin_paths", []):
        points += weights.get("admin_panel", 8)
        findings.append({"severity": "Medium", "type": "admin_panel", "title": f"Administrative path reachable: {panel['path']}", "detail": f"The path returned HTTP {panel['status']}.", "remediation": "Restrict administrative interfaces by network access controls and strong authentication."})
    for cve in cves or []:
        severity = str(cve.get("severity", "")).upper()
        key = {"CRITICAL": "cve_critical", "HIGH": "cve_high", "MEDIUM": "cve_medium"}.get(severity)
        if key:
            points += weights.get(key, 0)
            findings.append({"severity": severity.title(), "type": "cve", "title": cve.get("id", "CVE match"), "detail": cve.get("description", "Potential CVE match; verify applicability."), "remediation": "Verify affected version and apply the vendor security update or mitigation."})
    score = min(100, points)
    label = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    return {"score": score, "label": label, "findings": findings, "why": [f"{x['title']}: {x['detail']}" for x in findings] or ["No configured exposure rules were triggered."]}
