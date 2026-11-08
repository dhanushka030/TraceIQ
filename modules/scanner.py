"""Port scanning: Nmap when installed, a built-in TCP connect scanner otherwise.

Both engines return the same host/port/service records so the rest of the
pipeline (CVE matching, scoring, graph, reports) does not care which one ran.
"""
from __future__ import annotations
import re, shutil, socket, subprocess, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

PROFILES = {"quick": ("-F",), "standard": ("-sV", "--top-ports", "1000"), "deep": ("-sV", "-sC", "--top-ports", "1000")}

# Well-known service names for the built-in scanner (port -> name).
SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 67: "dhcps", 69: "tftp",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 512: "exec", 513: "login", 514: "shell", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "ms-wbt-server",
    5000: "http-alt", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 5985: "wsman", 6379: "redis",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
QUICK_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017)
FULL_PORTS = tuple(sorted(set(SERVICE_NAMES) | set(QUICK_PORTS) | {5001, 5002, 7001, 8001, 8082, 8180, 9091, 9999}))
HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8082, 8180, 8888, 9000, 9090, 9999}
TLS_PORTS = {443, 8443}

def nmap_available() -> bool:
    return shutil.which("nmap") is not None

def scan_engine() -> str:
    return "nmap" if nmap_available() else "builtin"

# ---------------------------------------------------------------- Nmap

def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Convert Nmap XML to stable host/port/service records."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        addresses = [a.get("addr", "") for a in host.findall("address")]
        hostnames = [n.get("name", "") for n in host.findall("./hostnames/hostname")]
        ports = []
        for item in host.findall("./ports/port"):
            state = item.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = item.find("service")
            ports.append({"port": int(item.get("portid", "0")), "protocol": item.get("protocol", "tcp"), "state": state.get("state"), "service": service.get("name", "unknown") if service is not None else "unknown", "product": service.get("product", "") if service is not None else "", "version": service.get("version", "") if service is not None else ""})
        hosts.append({"addresses": addresses, "hostnames": hostnames, "ports": ports})
    return hosts

def _run_nmap(target: str, profile: str, timeout: int) -> list[dict]:
    command = ["nmap", *PROFILES[profile], "-oX", "-", "--host-timeout", f"{min(timeout, 300)}s", target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 15, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Nmap scan failed.")
    return parse_nmap_xml(result.stdout)

# ------------------------------------------------------- built-in scanner

_SSH_RE = re.compile(r"^SSH-\d\.\d+-([A-Za-z]+)[_-]?([\w.\-]*)")
_SERVER_RE = re.compile(r"([A-Za-z][\w\- ]*?)/([\d][\w.\-]*)")

def parse_banner(port: int, banner: str) -> dict:
    """Derive service/product/version hints from a raw banner or HTTP Server header."""
    banner = (banner or "").strip()
    info = {"service": SERVICE_NAMES.get(port, "unknown"), "product": "", "version": ""}
    if not banner:
        return info
    ssh = _SSH_RE.match(banner)
    if ssh:
        info.update(service="ssh", product=ssh.group(1), version=ssh.group(2))
        return info
    first = banner.splitlines()[0]
    if first.startswith("220") and "FTP" in first.upper():
        info["service"] = "ftp"
        match = re.search(r"(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server)\s*v?([\d.]+)?", first, re.I)
        if match: info.update(product=match.group(1), version=match.group(2) or "")
        return info
    if first.startswith("220") and "SMTP" in first.upper():
        info["service"] = "smtp"
        match = re.search(r"(Postfix|Exim|Sendmail|Microsoft ESMTP)\s*v?([\d.]+)?", first, re.I)
        if match: info.update(product=match.group(1), version=match.group(2) or "")
        return info
    match = _SERVER_RE.search(banner)
    if match:
        product = match.group(1).strip()
        if product.lower() == "apache": product = "Apache httpd"
        info.update(product=product, version=match.group(2))
    return info

def _probe_port(host: str, port: int, timeout: float, grab: bool) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            if grab:
                try:
                    sock.settimeout(1.2)
                    if port in HTTP_PORTS:
                        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetSentry-TraceIQ\r\n\r\n".encode())
                        raw = sock.recv(2048).decode("latin-1", "replace")
                        header = next((l for l in raw.splitlines() if l.lower().startswith("server:")), "")
                        banner = header.split(":", 1)[1].strip() if header else ""
                    elif port not in TLS_PORTS:
                        banner = sock.recv(256).decode("latin-1", "replace")
                except OSError:
                    banner = ""
            info = parse_banner(port, banner)
            if port in TLS_PORTS and info["service"] == "unknown": info["service"] = "https"
            return {"port": port, "protocol": "tcp", "state": "open", **info}
    except OSError:
        return None

def connect_scan(host: str, profile: str = "quick", timeout: float = 0.8, workers: int = 64) -> list[dict]:
    """TCP connect scan with light banner grabbing. Requires no extra privileges."""
    ports = QUICK_PORTS if profile == "quick" else FULL_PORTS
    grab = profile != "quick"
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = [r for r in pool.map(lambda p: _probe_port(host, p, timeout, grab), ports) if r]
    hostnames = []
    try: hostnames = [socket.gethostbyaddr(host)[0]]
    except OSError: pass
    return [{"addresses": [host], "hostnames": hostnames, "ports": sorted(found, key=lambda p: p["port"])}]

# ------------------------------------------------------------- public API

def scan_target(target: str, profile: str = "quick", timeout: int = 180) -> list[dict]:
    """Scan with Nmap when available, otherwise the built-in connect scanner."""
    if profile not in PROFILES:
        raise ValueError("Unknown scan profile.")
    if nmap_available():
        return _run_nmap(target, profile, timeout)
    return connect_scan(target, profile)
