"""Explainable exposure scoring.

Every point in the score comes from a named rule, so each finding carries the
points it added and a category. The breakdown powers the dashboard gauge.
"""
from __future__ import annotations
from config import RISK_WEIGHTS, RISK_BANDS

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
CATEGORIES = ("Exposed services", "Software versions", "Known CVEs", "Web hardening", "Transport security", "Email security")

def risk_label(score: int) -> str:
    return next(name for name, floor in RISK_BANDS if score >= floor)

def score_exposure(hosts: list[dict], footprint: dict | None = None, cves: list[dict] | None = None, weights: dict | None = None) -> dict:
    weights = weights or RISK_WEIGHTS
    findings: list[dict] = []
    risky_ports: list[int] = []
    breakdown = {c: 0 for c in CATEGORIES}

    def add(severity, kind, category, title, detail, remediation, points=0):
        breakdown[category] += points
        findings.append({"severity": severity, "type": kind, "category": category, "points": points, "title": title, "detail": detail, "remediation": remediation})

    for host in hosts:
        for port in host.get("ports", []):
            value = weights.get("port", {}).get(str(port.get("port")), 0)
            if value:
                risky_ports.append(port.get("port"))
                service_name = str(port.get("service", "service")).replace("_", " ").title()
                add("High" if value >= 12 else "Medium", "risky_port", "Exposed services", f"Potentially risky service on port {port.get('port')}", f"{service_name} is reachable on port {port.get('port')}.", "Close the port if unused; restrict it to trusted networks and require strong authentication.", value)
            if port.get("product") and port.get("version"):
                add("Info", "version_disclosure", "Software versions", f"Version identified: {port['product']} {port['version']}", "Service version information was returned by the target.", "Keep the service patched and avoid exposing version banners where possible.")

    matched_products = {str(c.get("matched_product", "")).lower().split()[0] for c in cves or [] if c.get("matched_product")}
    counted_versions = set()
    for host in hosts:
        for port in host.get("ports", []):
            product, version = str(port.get("product", "")), str(port.get("version", ""))
            if product and version and any(token in product.lower() for token in matched_products) and (product, version) not in counted_versions:
                counted_versions.add((product, version))
                add("Medium", "outdated_version", "Software versions", f"Review detected version: {product} {version}", "A CVE keyword match references this product; confirm whether the detected version is affected before treating it as vulnerable.", "Check the vendor advisory and upgrade or apply the supported mitigation if this version is affected.", weights.get("outdated_version", 12))

    fp = footprint or {}
    http = fp.get("http", {})
    for header, present in http.get("security_headers", {}).items():
        if not present:
            add("Low", "missing_header", "Web hardening", f"Missing {header}", "A recommended browser security response header was not detected.", "Configure the web server to return this security header.", weights.get("missing_security_header", 4))
    if http and (http.get("status") is not None or http.get("security_headers")) and not http.get("https", False):
        add("Medium", "no_https", "Transport security", "HTTPS not confirmed", "No successful HTTPS response was confirmed.", "Enable HTTPS with a valid certificate and redirect HTTP traffic.", weights.get("no_https", 8))
    for panel in http.get("admin_paths", []):
        add("Medium", "admin_panel", "Web hardening", f"Administrative path reachable: {panel['path']}", f"The path returned HTTP {panel['status']}.", "Restrict administrative interfaces by network access controls and strong authentication.", weights.get("admin_panel", 8))

    tls = fp.get("tls") or {}
    if tls.get("available"):
        days = tls.get("days_left")
        if tls.get("trusted") is False and days == -1:
            add("High", "tls_expired", "Transport security", "TLS certificate has expired", tls.get("error") or "The server certificate is past its expiry date.", "Renew the certificate and automate renewal.", weights.get("tls_expired", 12))
        elif tls.get("trusted") is False:
            add("Medium", "tls_untrusted", "Transport security", "TLS certificate is not trusted", tls.get("error") or "The certificate could not be verified.", "Install a certificate from a trusted authority with the correct hostname.", weights.get("tls_untrusted", 8))
        elif isinstance(days, int) and days < 30:
            add("Low", "tls_expiring", "Transport security", f"TLS certificate expires in {days} day(s)", "The certificate is close to its expiry date.", "Renew the certificate before it expires.", weights.get("tls_expiring", 4))

    dns = fp.get("dns") or {}
    if "spf_present" in dns and dns["spf_present"] is False:
        add("Low", "missing_spf", "Email security", "No SPF record found", "Without SPF, receiving servers cannot check which hosts may send mail for this domain.", "Publish an SPF TXT record listing authorized senders.", weights.get("missing_spf", 3))
    if "dmarc_present" in dns and dns["dmarc_present"] is False:
        add("Low", "missing_dmarc", "Email security", "No DMARC policy found", "Without DMARC, spoofed mail using this domain is harder to detect and block.", "Publish a DMARC TXT record at _dmarc.<domain>, starting with p=none and monitoring reports.", weights.get("missing_dmarc", 3))

    for cve in cves or []:
        severity = str(cve.get("severity", "")).upper()
        key = {"CRITICAL": "cve_critical", "HIGH": "cve_high", "MEDIUM": "cve_medium"}.get(severity)
        if key:
            add(severity.title(), "cve", "Known CVEs", cve.get("id", "CVE match"), cve.get("description", "Potential CVE match; verify applicability."), "Verify affected version and apply the vendor security update or mitigation.", weights.get(key, 0))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["points"]))
    score = min(100, sum(breakdown.values()))
    return {"score": score, "label": risk_label(score), "findings": findings, "breakdown": breakdown, "risky_ports": risky_ports, "why": [f"{x['title']}: {x['detail']}" for x in findings] or ["No configured exposure rules were triggered."]}
