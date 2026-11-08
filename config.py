"""Application configuration and risk weights."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'netsentry.db'}"
SECRET_KEY = "change-this-secret-before-deployment"
SCAN_TIMEOUT = 180
SCAN_COOLDOWN_SECONDS = 10
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8
RISK_WEIGHTS = {
    "port": {"21": 12, "23": 20, "445": 18, "3389": 14, "3306": 12, "5432": 12, "27017": 15, "6379": 15, "9200": 12},
    "missing_security_header": 4, "no_https": 8, "outdated_version": 12,
    "admin_panel": 8, "cve_critical": 20, "cve_high": 12, "cve_medium": 6,
}
