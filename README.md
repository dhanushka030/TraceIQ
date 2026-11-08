# NetSentry TraceIQ

Context-aware network reconnaissance and exposure mapping for an Ethical Hacking / Network Security college mini project. TraceIQ combines target validation, WHOIS and DNS footprinting, bounded Nmap profiles, explainable exposure scoring, optional NVD CVE matching, an interactive graph, SQLite scan history, comparison, and downloadable reports.

> **Ethical use:** Scan only systems you own or have explicit permission to assess. The application permits loopback and private IP targets, `scanme.nmap.org`, and domains listed in `allowed_targets.json`. Every live scan requires a separate authorization confirmation.

## Setup

### Windows

1. Install Python 3.11 or later and Nmap from [nmap.org/download](https://nmap.org/download). Add Nmap's install folder to `PATH` and restart the terminal.
2. Open PowerShell in this folder and create a virtual environment:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux

Install Python 3.11+, Nmap, and the platform libraries needed by WeasyPrint. For Debian/Ubuntu, `sudo apt install python3.11 python3.11-venv nmap libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info`.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

From this directory:

```bash
python app.py
```

Visit `http://127.0.0.1:5000`. If Nmap is unavailable, the app still launches and Demo Mode remains available. For an offline demo, click **Load sample scan**. A live scan requires ticking the authorization box. Private subnets can be scanned by IP; add an explicitly approved domain to `allowed_targets.json` to allow it.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/scan` | Start an authorized scan (`target`, `profile`, `authorized: true`) |
| GET | `/api/scan/<id>/status` | Poll progress |
| GET | `/api/scan/<id>/results` | Read completed results |
| GET | `/api/scan/<id>/graph` | Get vis-network nodes and edges |
| GET | `/api/scan/<id>/report?format=pdf` | Download PDF, with HTML fallback; use `format=html` for HTML |
| GET | `/api/history` | List up to 200 scans |
| GET | `/api/compare?a=<id>&b=<id>` | Compare ports and risk score |
| GET | `/api/demo` | Read offline sample assessment |

## Architecture

```mermaid
flowchart LR
  UI[Dashboard HTML CSS JS] --> API[Flask API]
  API --> V[Target validator and allowlist]
  API --> F[WHOIS DNS HTTP footprint]
  API --> N[Nmap XML scanner]
  F --> R[Risk engine]
  N --> C[NVD matcher and offline fallback]
  C --> R
  R --> G[vis-network graph]
  API --> DB[(SQLite scans and CVE cache)]
  API --> RP[Jinja report and optional PDF]
```

## Demo script

1. Start the application and show the ethical-use disclaimer and target allowlist behavior.
2. Load sample data to show the dashboard, score explanation, CVE example, and exposure graph without network access.
3. If Nmap is installed and the course environment allows it, scan `127.0.0.1` or a deliberately prepared private lab VM after confirming authorization.
4. Open scan history, compare two completed scans, and download a report.

## Screenshot placeholder

Add a screenshot of the dashboard here after running the application: `![TraceIQ dashboard](docs/screenshot.png)`.

## Tests

```bash
pytest -q
```

Tests cover target normalization/scope, risky-port and header scoring, severity labels/capping, and Nmap XML parsing.

## Known limitations

- CVE keyword matches are triage hints; product/version strings may not map exactly to NVD CPE configurations. Confirm with vendor advisories.
- NVD availability and rate limits vary. SQLite cache and a small offline dataset provide limited fallback coverage.
- WHOIS and DNS access depend on local network and resolver configuration. Data sources may return incomplete or stale records.
- Nmap scripts and service detection can be intrusive; Deep mode is limited to approved targets and the top 1000 ports.
- The score is a transparent educational heuristic, not a compliance rating or proof of exploitability.
- PDF export depends on WeasyPrint and its native platform libraries. HTML download remains available if PDF conversion fails.
- Client-side graph and chart libraries load from public CDNs; an internet connection is needed for these visualizations unless vendored locally.
