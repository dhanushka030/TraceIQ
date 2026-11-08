import os, sys, tempfile
from pathlib import Path

# Isolate the database and make the project importable before app.py is imported.
os.environ["NETSENTRY_DB_BACKEND"] = "memory"  # tests must never touch the live Firestore project
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

@pytest.fixture()
def client():
    import app as netsentry
    netsentry.app.config["TESTING"] = True
    netsentry._last_scan = 0.0
    netsentry.store.clear_scans()
    with netsentry.app.test_client() as c:
        yield c
