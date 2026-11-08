"""SQLite persistence for scan history and cached CVE queries."""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(253), nullable=False, index=True)
    profile = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="queued")
    progress = db.Column(db.String(255), nullable=False, default="Queued")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)
    result_json = db.Column(db.JSON, nullable=True)
    error = db.Column(db.Text)

class CVECache(db.Model):
    product = db.Column(db.String(500), primary_key=True)
    records = db.Column(db.JSON, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

def cve_cache_adapter():
    class Cache:
        def get(self, key):
            row = CVECache.query.get(key)
            return row.records if row else None
        def __setitem__(self, key, value):
            row = CVECache.query.get(key)
            if row: row.records, row.updated_at = value, datetime.now(timezone.utc)
            else: db.session.add(CVECache(product=key, records=value))
            db.session.commit()
    return Cache()
