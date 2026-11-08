# NetSentry TraceIQ

Context-aware network reconnaissance and exposure mapping, built as an Ethical Hacking / Network Security mini project.

Enter a domain or IP you are allowed to test. TraceIQ looks up its public footprint (WHOIS, DNS, TLS certificate, subdomains, HTTP headers), scans for open ports with Nmap or its own built-in scanner, matches the detected software against known CVEs, and produces an exposure score where **every point is explained by a named finding**. Results appear on a dashboard with an exposure map, scan history and comparison, and downloadable reports.

![TraceIQ dashboard with the sample assessment](docs/screenshot.png)

> **Ethical use:** scan only systems you own or have explicit written permission to assess. The app allows loopback and private IP targets, `scanme.nmap.org`, and names listed in `allowed_targets.json`. Every scan needs a separate authorization tick. This is an educational tool: the score is a heuristic, CVE matches are keyword hints, and nothing here proves a system is exploitable.

## Database: Firebase (Firestore)

Scan history and the CVE cache are stored in Google **Cloud Firestore**.

1. In the [Firebase console](https://console.firebase.google.com) open your project, go to **Build > Firestore Database** and click **Create database** (production mode is fine; the server uses the Admin SDK).
2. Go to **Project settings > Service accounts > Generate new private key** and copy `project_id`, `client_email` and `private_key` into `.env` (see `.env.example`), or set `FIREBASE_SERVICE_ACCOUNT_PATH` to the downloaded JSON file.
3. Run the app. It checks the connection at startup and stops with a clear message if Firebase is unreachable.

Collections used: `scans` (one document per scan, ids 1, 2, 3 ...), `cve_cache`, and `meta` (the id counter). Names can be changed with `FIRESTORE_COLLECTION_SCANS` and `FIRESTORE_COLLECTION_CVE_CACHE`.

- **Moving old data:** if you used the earlier SQLite version, run `python scripts/migrate_sqlite_to_firestore.py` once (add `--dry-run` to preview). It copies your scans, keeps their ids, and never modifies `netsentry.db`.
- **Behind a VPN or TLS-inspecting proxy (for example Cloudflare WARP)?** On Windows the app builds its trust list from the Windows certificate store automatically, so Firebase connections work. To use your own bundle, set `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`.
- **Security:** `.env` and service-account keys are git-ignored. Never commit them. Rotate the private key in the Firebase console if it is ever exposed.
- **Tests never touch Firebase:** they run against an in-memory store (`NETSENTRY_DB_BACKEND=memory`).

## One-command setup

From a fresh clone, in the project folder:

| System | Command |
|---|---|
| Windows | `setup.bat` |
| Linux / macOS | `./setup.sh` (run `chmod +x setup.sh` first if needed) |

The script creates `.venv`, installs `requirements.txt`, checks for Nmap and prints install instructions if it is missing, runs the tests, checks that `.env` has your Firebase keys (creating it from `.env.example` if not), then starts the app. Set `NO_RUN=1` to stop after the tests. Python 3.11 or newer is required; Nmap is optional.

## Run

```bash
python app.py
```

Open <http://127.0.0.1:5000>. Set the `PORT` environment variable to use another port.

- **Sample assessment (no network needed):** click **Load sample assessment**, or open <http://127.0.0.1:5000/?demo=1>. It stores two sample scans (an earlier baseline and a newer one) so the map, report downloads and **Compare** all work immediately. They are marked as sample data and can be deleted from history.
- **Live scan:** enter a target, choose a depth, tick the authorization box and press **Start scan** (or `Ctrl+Enter`). Good lab targets are `127.0.0.1`, a private-network VM, or `scanme.nmap.org`.

### Scan engines

| Engine | When | Coverage |
|---|---|---|
| Nmap | Found on `PATH` at startup | Top 100 / top 1000 ports, service versions, default scripts |
| Built-in TCP scanner | Nmap not installed | About 27 common ports (quick) or about 110 (standard / deep), with banner grabbing |

`GET /api/health` reports which one is active. Install Nmap from <https://nmap.org/download> (Windows) or `sudo apt install nmap` / `brew install nmap`, then restart the app.

## Features

- Firestore storage for scan history and the CVE cache
- Target validation and allowlist, mandatory authorization, scan cooldown
- WHOIS (with timeout), DNS records, SPF/DMARC, subdomains, reverse DNS, TLS certificate, HTTP security headers
- CVE matching against NVD with one retry on rate limiting and an offline fallback (flagged on screen)
- Explainable score with a per-category breakdown and fix advice for every finding
- Exposure map (plain SVG, keyboard accessible) with labels placed clear of lines
- History with score trend sparklines, reopen, delete and two-scan comparison
- Reports as PDF, HTML or JSON, plus a print-ready page and findings export to CSV
- Copy any finding to the clipboard, tab title progress, and a risk-coloured favicon
- Light and dark themes, keyboard shortcuts, works offline (no CDN assets)

### Keyboard shortcuts

| Key | Action |
|---|---|
| `Ctrl+Enter` | Start scan |
| `Esc` | Close the help window, or dismiss messages |
| `D` | Toggle dark mode |
| `H` | Open the history panel |
| `R` | Download the report |
| `?` | Show shortcuts |

Single-key shortcuts are disabled while typing in a field.

## Tests

```bash
python -m pytest -q
```

The suite covers target validation, the full API lifecycle, the Nmap code path through a fake Nmap executable, the built-in scanner against a real local socket, NVD rate-limit and timeout handling, WHOIS failure, scoring, graph building and report generation. PDF export tries WeasyPrint, then headless Edge/Chrome, then falls back to HTML.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/scan` | Start a scan (`target`, `profile`, `authorized: true`) |
| GET | `/api/scan/<id>/status` | Poll progress |
| GET | `/api/scan/<id>/results` | Completed results |
| GET | `/api/scan/<id>/graph` | Map nodes and edges |
| GET | `/api/scan/<id>/report?format=pdf\|html\|json` | Download a report |
| DELETE | `/api/scan/<id>` | Delete a finished scan |
| GET | `/api/history` | Up to 200 saved scans |
| GET | `/api/compare?a=<id>&b=<id>` | Ports, findings and score change |
| POST | `/api/demo/seed` | Create (once) the two sample scans |
| GET | `/api/demo`, `/api/demo/report` | Sample data without touching the database |
| GET | `/api/health` | Status and Nmap availability |

## Known limitations

- CVE matches are keyword based; product strings may not map exactly to NVD records. Confirm with vendor advisories.
- NVD limits requests; the offline CVE list is small and is used only when the live lookup fails.
- WHOIS and DNS depend on your resolver and network. They are skipped for IPs and private hosts.
- The built-in scanner is a TCP connect scan of common ports. Install Nmap for broader, deeper scans.
- The score is an educational heuristic, not a compliance rating.
