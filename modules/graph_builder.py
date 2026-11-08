"""vis-network graph payload construction."""
def build_graph(target: str, hosts: list[dict], footprint: dict, cves: list[dict], risk: dict) -> dict:
    nodes, edges = [{"id": "target", "label": target, "group": risk.get("label", "Low"), "title": "Scan target"}], []
    idx = 0
    service_nodes = []
    for host in hosts:
        for addr in host.get("addresses", []) or [target]:
            idx += 1; hid = f"host-{idx}"; nodes.append({"id": hid, "label": addr, "group": risk.get("label", "Low")}); edges.append({"from": "target", "to": hid})
            for port in host.get("ports", []):
                idx += 1; pid = f"port-{idx}"; label = f"{port.get('port')}/{port.get('protocol')} {port.get('service')} {port.get('product', '')} {port.get('version', '')}".strip(); nodes.append({"id": pid, "label": label, "group": "service", "title": str(port)}); edges.append({"from": hid, "to": pid}); service_nodes.append((pid, port))
    for record in cves:
        idx += 1; cid = f"cve-{idx}"; nodes.append({"id": cid, "label": record.get("id", "CVE"), "group": record.get("severity", "Unknown"), "title": record.get("description", "")[:300]})
        matched = str(record.get("matched_product", "")).lower().split()[0:1]
        linked = [sid for sid, port in service_nodes if matched and matched[0] in f"{port.get('product', '')} {port.get('version', '')}".lower()]
        edges.extend({"from": sid, "to": cid} for sid in linked) if linked else edges.append({"from": "target", "to": cid})
    for kind, values in footprint.get("dns", {}).items():
        if not isinstance(values, list): continue
        for value in values[:10]:
            idx += 1; did=f"dns-{idx}"; nodes.append({"id":did,"label":f"{kind}: {value[:50]}","group":"dns"}); edges.append({"from":"target","to":did})
    return {"nodes": nodes, "edges": edges}
