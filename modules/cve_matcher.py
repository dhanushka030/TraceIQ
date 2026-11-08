"""NVD 2.0 lookup with offline fallback and scan-cache support."""
from __future__ import annotations
import json
from pathlib import Path
import requests
from config import NVD_API_URL, NVD_TIMEOUT

FALLBACK_PATH = Path(__file__).resolve().parents[1] / "data" / "offline_cves.json"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def _load_fallback() -> list[dict]:
    try: return json.loads(FALLBACK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): return []

def match_cves(services: list[dict], cache=None) -> list[dict]:
    """Return CVE hints for detected product/version strings.

    Live NVD answers are cached. Offline fallback answers are never cached, so a
    short outage cannot hide live results for the cache lifetime.
    """
    results, seen, fallback = [], set(), _load_fallback()
    for service in services:
        product = " ".join(x for x in (service.get("product"), service.get("version")) if x).strip()
        if not product: continue
        records = cache.get(product) if cache else None
        source = "cache"
        if records is None:
            try:
                response = requests.get(NVD_API_URL, params={"keywordSearch": product, "resultsPerPage": 10}, timeout=NVD_TIMEOUT, headers={"User-Agent": "NetSentry-TraceIQ/1.0"})
                response.raise_for_status(); records = _parse_nvd(response.json()); source = "nvd"
                if cache is not None: cache[product] = records
            except (requests.RequestException, ValueError, KeyError):
                token = product.lower().split()[0]
                records = [c for c in fallback if token in c.get("product", "").lower()]; source = "offline"
        for record in records or []:
            if record.get("id") not in seen:
                results.append({**record, "matched_product": product, "source": source})
                seen.add(record.get("id"))
    results.sort(key=lambda c: (SEVERITY_RANK.get(str(c.get("severity", "")).upper(), 9), -(c.get("cvss") or 0)))
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
