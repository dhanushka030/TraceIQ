"""One-time copy of scans from the old SQLite file (netsentry.db) into Firestore.

Usage (from the project folder):
    python scripts/migrate_sqlite_to_firestore.py            # copy, keeping scan ids
    python scripts/migrate_sqlite_to_firestore.py --dry-run  # show what would be copied

Sample scans (profile "demo") are skipped; the app recreates them on demand.
Scans already in Firestore are left untouched, so the script is safe to run twice.
The SQLite file is only read, never modified or deleted.
"""
import argparse, json, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from models.store import FirestoreStore, ScanRecord  # noqa: E402

def parse(value):
    if not value: return None
    dt = datetime.fromisoformat(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--db", default=str(ROOT / "netsentry.db")); ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not Path(args.db).is_file(): sys.exit(f"No SQLite file at {args.db}; nothing to migrate.")
    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True); con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM scan WHERE profile != 'demo' ORDER BY id").fetchall()
    print(f"Found {len(rows)} scan(s) to migrate.")
    if args.dry_run or not rows:
        for r in rows: print(f"  would copy #{r['id']} {r['target']} ({r['status']})")
        return
    store = FirestoreStore(); store.ping()
    copied = skipped = 0
    for r in rows:
        if store.get_scan(r["id"]):
            print(f"  #{r['id']} already in Firestore, skipped"); skipped += 1; continue
        result = json.loads(r["result_json"]) if r["result_json"] else None
        store.save_scan(ScanRecord(r["id"], r["target"], r["profile"], r["status"], r["progress"], parse(r["created_at"]), parse(r["completed_at"]), result, r["error"]))
        print(f"  #{r['id']} {r['target']} copied"); copied += 1
    # Make new scans continue after the highest migrated id.
    top = max(r["id"] for r in rows)
    snap = store.counter.get()
    if top > ((snap.to_dict() or {}).get("value", 0) if snap.exists else 0): store.counter.set({"value": top})
    print(f"Done: {copied} copied, {skipped} skipped. Next new scan id will be above #{top}.")

if __name__ == "__main__":
    main()
