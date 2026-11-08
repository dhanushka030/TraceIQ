"""WHOIS, DNS, TLS, HTTP headers, and lightweight web exposure collection."""
from __future__ import annotations
import ipaddress, socket, ssl
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
import requests

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")
COMMON_SUBDOMAINS = ("www", "mail", "ftp", "api", "dev", "test", "staging", "admin", "vpn", "blog", "portal", "git", "cdn", "ns1", "smtp")
UA = {"User-Agent": "NetSentry-TraceIQ/1.0 (authorized assessment)"}

def _is_ip(value: str) -> bool:
    try: ipaddress.ip_address(value); return True
    except ValueError: return False

def _is_local(value: str) -> bool:
    if value == "localhost": return True
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def _with_timeout(func, seconds, *args):
    """Run a blocking lookup (python-whois has no timeout of its own) with a hard cap."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(func, *args).result(timeout=seconds)
    except FutureTimeout:
        raise TimeoutError(f"timed out after {seconds}s")
    finally:
        pool.shutdown(wait=False)

def collect_dns(target: str) -> dict:
    import dns.resolver
    out = {}
    for kind in DNS_TYPES:
        try: out[kind] = [r.to_text() for r in dns.resolver.resolve(target, kind, lifetime=3)]
        except Exception: out[kind] = []
    out["spf_present"] = any("v=spf1" in x.lower() for x in out.get("TXT", []))
    out["dmarc_present"] = _has_txt("_dmarc." + target)
    return out

def collect_whois(target: str) -> dict:
    import whois
    w = whois.whois(target)
    out = {}
    for key in ("registrar", "creation_date", "expiration_date", "name_servers", "org", "country"):
        value = getattr(w, key, None) or (w.get(key) if hasattr(w, "get") else None)
        if isinstance(value, (list, tuple, set)): out[key] = sorted({str(v) for v in value})
        else: out[key] = str(value) if value else None
    return out

def find_subdomains(target: str, names=COMMON_SUBDOMAINS) -> list[dict]:
    """Resolve a short list of common subdomains; this is lookup only, not brute-forcing."""
    import dns.resolver
    def probe(name):
        fqdn = f"{name}.{target}"
        try: return {"name": fqdn, "addresses": [r.to_text() for r in dns.resolver.resolve(fqdn, "A", lifetime=2)]}
        except Exception: return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        return [r for r in pool.map(probe, names) if r]

def collect_tls(host: str, port: int = 443) -> dict:
    """Read the certificate. Untrusted certificates are reported, not trusted."""
    info = {"available": False, "trusted": None, "issuer": None, "subject": None, "not_after": None, "days_left": None, "error": None}
    def parse(cert):
        flat = lambda rdns: ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)
        info.update(available=True, issuer=flat(cert.get("issuer", ())), subject=flat(cert.get("subject", ())), not_after=cert.get("notAfter"))
        if cert.get("notAfter"):
            end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            info["days_left"] = (end - datetime.now(timezone.utc)).days
    try:
        with socket.create_connection((host, port), timeout=4) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            info["trusted"] = True
            parse(tls.getpeercert())
    except ssl.SSLCertVerificationError as exc:
        info.update(available=True, trusted=False, error=exc.verify_message or str(exc))
        info["days_left"] = -1 if "expired" in str(exc).lower() else None
    except (OSError, ssl.SSLError) as exc:
        info["error"] = f"No TLS service reachable: {exc.__class__.__name__}"
    return info

def collect_http(target: str) -> dict:
    http = {"headers": {}, "security_headers": {}, "admin_paths": []}
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{target}", timeout=4, allow_redirects=True, headers=UA)
            http.update({"url": response.url, "status": response.status_code, "headers": dict(response.headers), "tech_hints": {k: response.headers.get(k) for k in ("Server", "X-Powered-By") if response.headers.get(k)}, "security_headers": {h: bool(response.headers.get(h)) for h in SECURITY_HEADERS}})
            http["https"] = response.url.lower().startswith("https:")
            for path in ("/admin", "/phpmyadmin", "/login"):
                try:
                    check = requests.get(f"{scheme}://{target}{path}", timeout=2, allow_redirects=False, headers=UA)
                    if check.status_code in (200, 401, 403): http["admin_paths"].append({"path": path, "status": check.status_code})
                except requests.RequestException: pass
            break
        except requests.RequestException:
            continue
    return http

def collect_footprint(target: str) -> dict:
    local, is_ip = _is_local(target), _is_ip(target)
    data = {"target": target, "dns": {}, "whois": {}, "reverse_dns": [], "subdomains": [], "tls": {}, "http": {"headers": {}, "security_headers": {}, "admin_paths": []}, "errors": [], "notes": []}
    if is_ip or local:
        data["notes"].append("DNS records and WHOIS apply to registered domain names, so they were skipped for this target.")
    else:
        try: data["dns"] = collect_dns(target)
        except Exception as exc: data["errors"].append(f"DNS lookup unavailable: {exc}")
        try: data["whois"] = _with_timeout(collect_whois, 10, target)
        except Exception as exc:  # any failure: the dashboard shows "WHOIS unavailable", the scan continues
            data["whois"], data["whois_error"] = None, str(exc) or exc.__class__.__name__
        try: data["subdomains"] = find_subdomains(target)
        except Exception as exc: data["errors"].append(f"Subdomain lookup unavailable: {exc}")
    try:
        for addr in sorted({x[4][0] for x in socket.getaddrinfo(target, None)}):
            try: data["reverse_dns"].append({"ip": addr, "name": socket.gethostbyaddr(addr)[0]})
            except OSError: pass
    except OSError: pass
    data["tls"] = collect_tls(target)
    data["http"] = collect_http(target)
    return data

def _has_txt(name: str) -> bool:
    try:
        import dns.resolver
        return any("v=dmarc1" in r.to_text().lower() for r in dns.resolver.resolve(name, "TXT", lifetime=3))
    except Exception: return False
