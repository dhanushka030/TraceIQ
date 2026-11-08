"""Storage layer: scan history and the CVE cache, stored in Google Firestore.

Scan ids are small sequential integers (kept by a counter document), so API URLs and the UI
are unchanged from the SQLite version. A MemoryStore exists only for automated tests.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import logging
from config import (CVE_CACHE_TTL_HOURS, DB_BACKEND, firebase_configured, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_PROJECT_ID,
                    FIREBASE_SERVICE_ACCOUNT_PATH, FIRESTORE_COLLECTION_CVE_CACHE, FIRESTORE_COLLECTION_SCANS)

log = logging.getLogger("netsentry.store")
FIELDS = ("target", "profile", "status", "progress", "created_at", "completed_at", "result_json", "error")

def _utc(value):
    """Both backends hand back timezone-aware UTC datetimes."""
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)

class ScanRecord:
    """Plain scan object used by routes and reports, independent of the backend."""
    def __init__(self, id=None, target="", profile="quick", status="queued", progress="Queued", created_at=None, completed_at=None, result_json=None, error=None):
        self.id, self.target, self.profile, self.status, self.progress = id, target, profile, status, progress
        self.created_at = _utc(created_at) or datetime.now(timezone.utc)
        self.completed_at, self.result_json, self.error = _utc(completed_at), result_json, error

class Store:
    backend = "base"
    def create_scan(self, target, profile, **extra) -> ScanRecord: raise NotImplementedError
    def get_scan(self, scan_id) -> ScanRecord | None: raise NotImplementedError
    def save_scan(self, scan: ScanRecord) -> None: raise NotImplementedError
    def list_scans(self, limit=200) -> list[ScanRecord]: raise NotImplementedError
    def delete_scan(self, scan_id) -> None: raise NotImplementedError
    def scans_by_profile(self, profile) -> list[ScanRecord]: raise NotImplementedError
    def fail_stale(self) -> int: raise NotImplementedError
    def clear_scans(self) -> None: raise NotImplementedError
    def cve_cache_get(self, key): raise NotImplementedError
    def cve_cache_set(self, key, records) -> None: raise NotImplementedError
    def cache_adapter(self):
        store = self
        class Cache:
            def get(self, key): return store.cve_cache_get(key)
            def __setitem__(self, key, value): store.cve_cache_set(key, value)
        return Cache()
    def ping(self) -> None: pass

# ------------------------------------------------------- in-memory (tests)

class MemoryStore(Store):
    """Process-local store for automated tests only: nothing is persisted and no network is used."""
    backend = "memory"
    def __init__(self):
        self.scans, self.cache, self.next_id = {}, {}, 1
    def create_scan(self, target, profile, **extra):
        scan = ScanRecord(self.next_id, target, profile, **extra); self.scans[scan.id] = scan; self.next_id += 1; return scan
    def get_scan(self, scan_id): return self.scans.get(scan_id)
    def save_scan(self, scan): self.scans[scan.id] = scan
    def list_scans(self, limit=200): return sorted(self.scans.values(), key=lambda s: s.created_at, reverse=True)[:limit]
    def delete_scan(self, scan_id): self.scans.pop(scan_id, None)
    def scans_by_profile(self, profile): return sorted((s for s in self.scans.values() if s.profile == profile), key=lambda s: s.created_at)
    def fail_stale(self):
        stale = [s for s in self.scans.values() if s.status in ("queued", "running")]
        for s in stale: s.status, s.progress, s.error = "failed", "Interrupted", "The application restarted before this scan finished."
        return len(stale)
    def clear_scans(self): self.scans.clear(); self.next_id = 1
    def cve_cache_get(self, key):
        hit = self.cache.get(key)
        return hit[1] if hit and datetime.now(timezone.utc) - hit[0] <= timedelta(hours=CVE_CACHE_TTL_HOURS) else None
    def cve_cache_set(self, key, records): self.cache[key] = (datetime.now(timezone.utc), records)

# ------------------------------------------------------------ Firestore

def _use_system_trust_store() -> None:
    """gRPC ships its own CA list and ignores the Windows certificate store, which breaks behind a
    TLS-inspecting proxy or VPN (Cloudflare WARP, antivirus). Build a bundle from certifi plus the
    system roots the user already trusts, and point gRPC at it. Skipped if the user set their own."""
    import os, sys, tempfile
    from pathlib import Path
    if os.environ.get("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH") or sys.platform != "win32": return
    try:
        import ssl, certifi
        pems = [Path(certifi.where()).read_text(encoding="utf-8")]
        for store_name in ("ROOT", "CA"):
            pems += [ssl.DER_cert_to_PEM_cert(der) for der, encoding, _ in ssl.enum_certificates(store_name) if encoding == "x509_asn"]
        bundle = Path(tempfile.gettempdir()) / "netsentry-grpc-roots.pem"
        bundle.write_text("\n".join(pems), encoding="utf-8")
        os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"] = str(bundle)       # Firestore (gRPC)
        os.environ.setdefault("REQUESTS_CA_BUNDLE", str(bundle))           # OAuth token fetch and other requests calls
        os.environ.setdefault("SSL_CERT_FILE", str(bundle))
    except Exception as exc:  # fall back to gRPC's built-in roots
        log.warning("Could not load the system certificate store for gRPC: %s", exc)

class FirestoreStore(Store):
    backend = "firestore"
    def __init__(self):
        _use_system_trust_store()
        import firebase_admin
        from firebase_admin import credentials, firestore
        from pathlib import Path
        self._firestore = firestore
        if not firebase_admin._apps:
            if FIREBASE_SERVICE_ACCOUNT_PATH and Path(FIREBASE_SERVICE_ACCOUNT_PATH).is_file():
                cred = credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_PATH)
            else:
                if FIREBASE_SERVICE_ACCOUNT_PATH: log.warning("FIREBASE_SERVICE_ACCOUNT_PATH does not point to a file; using the individual key fields instead.")
                cred = credentials.Certificate({"type": "service_account", "project_id": FIREBASE_PROJECT_ID, "client_email": FIREBASE_CLIENT_EMAIL,
                                                "private_key": FIREBASE_PRIVATE_KEY, "token_uri": "https://oauth2.googleapis.com/token"})
            firebase_admin.initialize_app(cred, {"projectId": FIREBASE_PROJECT_ID} if FIREBASE_PROJECT_ID else None)
        self.client = firestore.client()
        self.scans = self.client.collection(FIRESTORE_COLLECTION_SCANS)
        self.cache = self.client.collection(FIRESTORE_COLLECTION_CVE_CACHE)
        self.counter = self.client.collection("meta").document(f"{FIRESTORE_COLLECTION_SCANS}_counter")

    def ping(self):
        """Fail fast with a readable error if credentials, network or the database are wrong."""
        try: self.counter.get(timeout=20)
        except Exception as exc:
            raise RuntimeError(f"Could not reach Firestore project '{FIREBASE_PROJECT_ID}': {type(exc).__name__}: {str(exc)[:300]}") from exc

    def _next_id(self) -> int:
        firestore = self._firestore
        @firestore.transactional
        def bump(tx):
            snap = self.counter.get(transaction=tx)
            n = (snap.to_dict() or {}).get("value", 0) + 1 if snap.exists else 1
            tx.set(self.counter, {"value": n}); return n
        return bump(self.client.transaction())

    def _rec(self, doc):
        if not doc.exists: return None
        d = doc.to_dict()
        return ScanRecord(int(doc.id), **{f: d.get(f) for f in FIELDS if f in d})

    def _data(self, scan): return {f: getattr(scan, f) for f in FIELDS}

    def create_scan(self, target, profile, **extra):
        scan = ScanRecord(self._next_id(), target, profile, **extra)
        self.scans.document(str(scan.id)).set(self._data(scan)); return scan
    def get_scan(self, scan_id): return self._rec(self.scans.document(str(scan_id)).get())
    def save_scan(self, scan): self.scans.document(str(scan.id)).set(self._data(scan))
    def list_scans(self, limit=200):
        return [self._rec(d) for d in self.scans.order_by("created_at", direction=self._firestore.Query.DESCENDING).limit(limit).stream()]
    def delete_scan(self, scan_id): self.scans.document(str(scan_id)).delete()
    def scans_by_profile(self, profile):
        from google.cloud.firestore_v1.base_query import FieldFilter
        return sorted((self._rec(d) for d in self.scans.where(filter=FieldFilter("profile", "==", profile)).stream()), key=lambda s: s.created_at)
    def fail_stale(self):
        from google.cloud.firestore_v1.base_query import FieldFilter
        n = 0
        for d in self.scans.where(filter=FieldFilter("status", "in", ["queued", "running"])).stream():
            d.reference.update({"status": "failed", "progress": "Interrupted", "error": "The application restarted before this scan finished."}); n += 1
        return n
    def clear_scans(self):
        for d in self.scans.stream(): d.reference.delete()
        self.counter.delete()
    def cve_cache_get(self, key):
        doc = self.cache.document(_cache_id(key)).get()
        if not doc.exists: return None
        d = doc.to_dict()
        if datetime.now(timezone.utc) - _utc(d.get("updated_at")) > timedelta(hours=CVE_CACHE_TTL_HOURS): return None
        return d.get("records")
    def cve_cache_set(self, key, records):
        self.cache.document(_cache_id(key)).set({"product": key, "records": records, "updated_at": datetime.now(timezone.utc)})

def _cache_id(key: str) -> str:
    """Firestore document ids cannot contain '/' and are limited in size."""
    import hashlib
    return hashlib.sha256(key.lower().encode()).hexdigest()[:40]

def create_store(app=None, backend: str | None = None) -> Store:
    """Firestore is the database. "memory" exists only so tests never touch a live project."""
    backend = (backend or DB_BACKEND).lower()
    if backend == "memory": return MemoryStore()
    if backend != "firestore": raise RuntimeError(f"Unknown NETSENTRY_DB_BACKEND '{backend}'. Use firestore.")
    if not firebase_configured():
        raise RuntimeError("Firebase is not configured. Fill FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY (or FIREBASE_SERVICE_ACCOUNT_PATH) in .env.")
    store = FirestoreStore(); store.ping(); return store
