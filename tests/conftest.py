import os, sys, tempfile
from pathlib import Path

# Isolate the database and make the project importable before app.py is imported.
os.environ["NETSENTRY_DB"] = str(Path(tempfile.mkdtemp()) / "test.db")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

@pytest.fixture()
def client():
    import app as netsentry
    netsentry.app.config["TESTING"] = True
    netsentry._last_scan = 0.0
    with netsentry.app.app_context():
        netsentry.db.session.query(netsentry.Scan).delete()
        netsentry.db.session.commit()
    with netsentry.app.test_client() as c:
        yield c
