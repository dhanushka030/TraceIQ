"""NVD 2.0 lookup with offline fallback and scan-cache support."""
from __future__ import annotations
import json
from pathlib import Path
import requests
from config import NVD_API_URL, NVD_TIMEOUT

def match_cves(services: list[dict], cache=None) -> list[dict]:
    results, seen = [], set()
    fallback_path = Path(__file__).resolve().parents[1] / "data" / "offline_cves.json"
    try: fallback = json.loads(fallback_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): fallback = []
    for service in services:
        product = " ".join(x for x in (service.get("product"), service.get("version")) if x).strip()
        if not product: continue
        cached = cache.get(product) if cache else None
        records = cached if cached is not None else None
        if records is None:
            try:
                response = requests.get(NVD_API_URL, params={"keywordSearch": product, "resultsPerPage": 10}, timeout=NVD_TIMEOUT, headers={"User-Agent": "NetSentry-TraceIQ/1.0"})
                response.raise_for_status(); records = _parse_nvd(response.json())
            except (requests.RequestException, ValueError, KeyError):
                records = [c for c in fallback if product.lower().split()[0] in c.get("product", "").lower()]
            if cache: cache[product] = records
        for record in records or []:
            if record.get("id") not in seen:
                results.append({**record, "matched_product": product})
                seen.add(record.get("id"))
    return results

def _parse_nvd(payload: dict) -> list[dict]:
    output = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {}); metrics = cve.get("metrics", {})
        metric = next((arr[0] for key, arr in metrics.items() if key.startswith("cvssMetric") and arr), {})
        cvss = metric.get("cvssData", {})
        description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        output.append({"id": cve.get("id"), "cvss": cvss.get("baseScore"), "severity": cvss.get("baseSeverity", metric.get("baseSeverity", "Unknown")), "description": description[:1000]})
    return output
