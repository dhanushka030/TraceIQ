"""Nmap execution and safe XML result parsing."""
from __future__ import annotations
import shutil, subprocess, xml.etree.ElementTree as ET

PROFILES = {"quick": ("-F",), "standard": ("-sV", "--top-ports", "1000"), "deep": ("-sV", "-sC", "--top-ports", "1000")}

def nmap_available() -> bool:
    return shutil.which("nmap") is not None

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

def scan_target(target: str, profile: str = "quick", timeout: int = 180) -> list[dict]:
    if profile not in PROFILES:
        raise ValueError("Unknown scan profile.")
    if not nmap_available():
        raise RuntimeError("Nmap is not installed or is not available on PATH. Install Nmap, or use Demo Mode.")
    command = ["nmap", *PROFILES[profile], "-oX", "-", "--host-timeout", f"{min(timeout, 300)}s", target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 15, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Nmap scan failed.")
    return parse_nmap_xml(result.stdout)
