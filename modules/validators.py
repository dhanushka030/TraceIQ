"""Input validation and strict ethical scan scope enforcement."""
from __future__ import annotations
import ipaddress, json, re, socket
from pathlib import Path
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10"))

def normalize_target(raw: str) -> str:
    """Return a safe hostname/IP; reject URLs, shell syntax, and malformed names."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 253:
        raise ValueError("Enter a valid domain name or IP address.")
    value = raw.strip().lower().rstrip(".")
    if any(c in value for c in "/\\@?#;|&$`\n\r\t "):
        raise ValueError("Enter only a domain name or IP address, without a URL or extra characters.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError("Enter a valid domain name or IP address.")
        return value

def is_private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return any(address in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False

def resolve_addresses(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except OSError:
        return []

def preferred_address(addresses: list[str]) -> str:
    """Pick the address to scan: IPv4 first (what Nmap expects by default), IPv6 only if nothing else."""
    return next((a for a in addresses if ":" not in a), addresses[0])

def is_allowed_target(target: str, allowlist_path: Path | None = None, resolver=resolve_addresses) -> bool:
    """Only permit loopback/private targets, scanme.nmap.org, or explicit entries."""
    path = allowlist_path or Path(__file__).resolve().parents[1] / "allowed_targets.json"
    try:
        allowlist = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        allowlist = []
    allowlist = {str(item).strip().lower().rstrip(".") for item in allowlist if isinstance(item, str)}
    if target in {"localhost", "scanme.nmap.org"} or target in allowlist or is_private_address(target):
        return True
    # A public name is permitted only by explicit allowlist entry. For private names
    # outside the file, require every resolved address to be within private ranges.
    addresses = resolver(target)
    return bool(addresses) and all(is_private_address(address) for address in addresses)

def validate_target(raw: str, allowlist_path: Path | None = None) -> str:
    target = normalize_target(raw)
    if not is_allowed_target(target, allowlist_path):
        raise ValueError("Target is outside the permitted scan scope. Allowed: localhost, private IP ranges, scanme.nmap.org, or a target in allowed_targets.json.")
    return target
