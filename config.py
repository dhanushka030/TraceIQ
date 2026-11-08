"""Application configuration and risk weights."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("NETSENTRY_DB_URL") or f"sqlite:///{os.environ.get('NETSENTRY_DB') or BASE_DIR / 'netsentry.db'}"
# Generated per process unless NETSENTRY_SECRET_KEY is set; the app keeps no login sessions.
SECRET_KEY = os.environ.get("NETSENTRY_SECRET_KEY") or os.urandom(32).hex()
SCAN_TIMEOUT = 180
SCAN_COOLDOWN_SECONDS = 10
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8
CVE_CACHE_TTL_HOURS = 24

RISK_WEIGHTS = {
    "port": {
        "21": 12, "23": 20, "25": 6, "69": 12, "110": 8, "111": 10, "135": 12, "137": 10, "139": 14,
        "143": 6, "161": 10, "445": 18, "512": 14, "513": 14, "514": 14, "1433": 12, "1521": 12,
        "2049": 10, "3306": 12, "3389": 14, "5432": 12, "5900": 14, "6379": 15, "9200": 12,
        "11211": 12, "27017": 15,
    },
    "missing_security_header": 4, "no_https": 8, "outdated_version": 12,
    "admin_panel": 8, "cve_critical": 20, "cve_high": 12, "cve_medium": 6,
    "tls_expired": 12, "tls_expiring": 4, "tls_untrusted": 8,
    "missing_spf": 3, "missing_dmarc": 3,
}

# Score bands (inclusive lower bound) used for the label and the gauge.
RISK_BANDS = (("Critical", 75), ("High", 50), ("Medium", 25), ("Low", 0))
