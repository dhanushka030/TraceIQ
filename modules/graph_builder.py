"""Exposure-graph payload: typed nodes and edges rendered by the dashboard's SVG map."""
from __future__ import annotations

MAX_DNS_NODES = 12

def build_graph(target: str, hosts: list[dict], footprint: dict, cves: list[dict], risk: dict) -> dict:
    """Nodes carry `kind` (target/host/service/cve/dns) and `severity` so the UI never guesses."""
    nodes = [{"id": "target", "label": target, "kind": "target", "severity": risk.get("label", "Low"), "title": "Scan target"}]
    edges, service_nodes, idx = [], [], 0
    risky = {str(p) for p in (risk.get("risky_ports") or [])}
    for host in hosts:
        for addr in host.get("addresses", []) or [target]:
            idx += 1; hid = f"host-{idx}"
            nodes.append({"id": hid, "label": addr, "kind": "host", "severity": "Info", "title": "Host " + addr})
            edges.append({"from": "target", "to": hid})
            for port in host.get("ports", []):
                idx += 1; pid = f"port-{idx}"
                label = f"{port.get('port')}/{port.get('protocol')} {port.get('service')}".strip()
                detail = " ".join(x for x in (port.get("product"), port.get("version")) if x)
                nodes.append({"id": pid, "label": label, "kind": "service", "severity": "High" if str(port.get("port")) in risky else "Info", "title": detail or "Service", "port": port.get("port")})
                edges.append({"from": hid, "to": pid}); service_nodes.append((pid, port))
    for record in cves:
        idx += 1; cid = f"cve-{idx}"
        nodes.append({"id": cid, "label": record.get("id", "CVE"), "kind": "cve", "severity": str(record.get("severity", "Medium")).title(), "title": (record.get("description") or "")[:300]})
        token = str(record.get("matched_product", "")).lower().split()[:1]
        linked = [sid for sid, port in service_nodes if token and token[0] in f"{port.get('product', '')} {port.get('version', '')}".lower()]
        if linked: edges.extend({"from": sid, "to": cid} for sid in linked)
        else: edges.append({"from": "target", "to": cid})
    dns_added = 0
    for kind, values in (footprint.get("dns") or {}).items():
        if not isinstance(values, list): continue
        for value in values[:3]:
            if dns_added >= MAX_DNS_NODES: break
            idx += 1; did = f"dns-{idx}"; dns_added += 1
            nodes.append({"id": did, "label": f"{kind} {str(value)[:40]}", "kind": "dns", "severity": "Info", "title": f"{kind} record"})
            edges.append({"from": "target", "to": did})
    return {"nodes": nodes, "edges": edges}
