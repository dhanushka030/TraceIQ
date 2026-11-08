"""Application configuration and risk weights."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def _load_dotenv(path: Path) -> None:
    """Minimal .env reader (KEY=VALUE, # comments). Real environment variables always win."""
    try: lines = path.read_text(encoding="utf-8").splitlines()
    except OSError: return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'": value = value[1:-1]
        os.environ.setdefault(key.strip(), value)

_load_dotenv(BASE_DIR / ".env")

# Generated per process unless NETSENTRY_SECRET_KEY is set; the app keeps no login sessions.
SECRET_KEY = os.environ.get("NETSENTRY_SECRET_KEY") or os.urandom(32).hex()
# Public deployments (Render etc.): refuse loopback/private targets so the server cannot be used to probe its own network.
PUBLIC_MODE = os.environ.get("NETSENTRY_PUBLIC_MODE", "").strip().lower() in ("1", "true", "yes", "on")
# Optional "user:password" that protects the whole site (except /api/health) with HTTP Basic auth.
BASIC_AUTH = os.environ.get("NETSENTRY_BASIC_AUTH", "")
SCAN_TIMEOUT = 180
SCAN_COOLDOWN_SECONDS = 10
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 8
CVE_CACHE_TTL_HOURS = 24

# ---- Firebase / Firestore -------------------------------------------------
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "")
FIREBASE_CLIENT_EMAIL = os.environ.get("FIREBASE_CLIENT_EMAIL", "")
FIREBASE_PRIVATE_KEY = os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
FIREBASE_SERVICE_ACCOUNT_PATH = os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH", "")
FIRESTORE_COLLECTION_SCANS = os.environ.get("FIRESTORE_COLLECTION_SCANS") or "scans"
FIRESTORE_COLLECTION_CVE_CACHE = os.environ.get("FIRESTORE_COLLECTION_CVE_CACHE") or "cve_cache"

def firebase_configured() -> bool:
    key_file = FIREBASE_SERVICE_ACCOUNT_PATH and Path(FIREBASE_SERVICE_ACCOUNT_PATH).is_file()
    return bool(key_file or (FIREBASE_PROJECT_ID and FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY))

# Firestore is the database. NETSENTRY_DB_BACKEND=memory is for automated tests only.
DB_BACKEND = (os.environ.get("NETSENTRY_DB_BACKEND") or "firestore").lower()

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
