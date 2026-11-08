"""WHOIS, DNS, HTTP headers, and lightweight web exposure collection."""
from __future__ import annotations
import socket
from urllib.parse import urlparse
import requests

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")

def collect_footprint(target: str) -> dict:
    data = {"target": target, "dns": {}, "whois": {}, "reverse_dns": [], "http": {"headers": {}, "security_headers": {}, "admin_paths": []}, "errors": []}
    try:
        import dns.resolver
        for kind in DNS_TYPES:
            try:
                data["dns"][kind] = [r.to_text() for r in dns.resolver.resolve(target, kind, lifetime=3)]
            except Exception:
                data["dns"][kind] = []
        data["dns"]["spf_present"] = any("v=spf1" in x.lower() for x in data["dns"].get("TXT", []))
        data["dns"]["dmarc_present"] = _has_txt("_dmarc." + target)
    except Exception as exc:
        data["errors"].append(f"DNS lookup unavailable: {exc}")
    try:
        import whois
        w = whois.whois(target)
        for key in ("registrar", "creation_date", "expiration_date", "name_servers", "org", "country"):
            value = getattr(w, key, None)
            data["whois"][key] = [str(v) for v in value] if isinstance(value, (list, tuple)) else str(value) if value else None
    except Exception as exc:
        data["errors"].append(f"WHOIS lookup unavailable: {exc}")
    try:
        for addr in {x[4][0] for x in socket.getaddrinfo(target, None)}:
            try: data["reverse_dns"].append({"ip": addr, "name": socket.gethostbyaddr(addr)[0]})
            except OSError: pass
    except OSError: pass
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{target}", timeout=4, allow_redirects=True, headers={"User-Agent": "NetSentry-TraceIQ/1.0 (authorized assessment)"})
            data["http"].update({"url": response.url, "status": response.status_code, "headers": dict(response.headers), "tech_hints": {k: response.headers.get(k) for k in ("Server", "X-Powered-By") if response.headers.get(k)}, "security_headers": {h: bool(response.headers.get(h)) for h in SECURITY_HEADERS}})
            data["http"]["https"] = response.url.lower().startswith("https:")
            for path in ("/admin", "/phpmyadmin", "/login"):
                try:
                    check = requests.get(f"{scheme}://{target}{path}", timeout=2, allow_redirects=False, headers={"User-Agent": "NetSentry-TraceIQ/1.0"})
                    if check.status_code in (200, 401, 403): data["http"]["admin_paths"].append({"path": path, "status": check.status_code})
                except requests.RequestException: pass
            break
        except requests.RequestException:
            continue
    return data

def _has_txt(name: str) -> bool:
    try:
        import dns.resolver
        return any("v=dmarc1" in r.to_text().lower() for r in dns.resolver.resolve(name, "TXT", lifetime=3))
    except Exception: return False
