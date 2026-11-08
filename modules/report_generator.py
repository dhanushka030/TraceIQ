"""HTML and PDF report generation.

PDF engines, in order: WeasyPrint (needs GTK/Pango libraries), then a headless
Chromium-family browser (Edge ships with Windows). If neither works the caller
falls back to the HTML report, which is always available.
"""
from __future__ import annotations
import os, shutil, subprocess, tempfile
from pathlib import Path
from flask import render_template

DISCLAIMER = "Only scan systems you own or have explicit permission to assess. This report is an educational point-in-time assessment, not proof of exploitability or a substitute for a professional security review."

_BROWSER_PATHS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

def render_report(scan):
    data = scan.result_json or {}
    return render_template("report.html", scan=scan, data=data, disclaimer=DISCLAIMER)

def _weasy_pdf(html: str) -> bytes | None:
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except Exception:
        return None

def _browser_pdf(html: str) -> bytes | None:
    exe = next((p for p in _BROWSER_PATHS if os.path.exists(p)), None) or shutil.which("msedge") or shutil.which("chromium") or shutil.which("google-chrome")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        src, out = Path(tmp, "report.html"), Path(tmp, "report.pdf")
        src.write_text(html, encoding="utf-8")
        for attempt in range(2):  # the first launch with a fresh profile occasionally exits without output
            try:
                subprocess.run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--user-data-dir={Path(tmp, f'profile{attempt}')}", f"--print-to-pdf={out}", src.as_uri()], capture_output=True, timeout=45, check=False)
            except (OSError, subprocess.SubprocessError):
                return None
            if out.exists() and out.stat().st_size > 0:
                return out.read_bytes()
        return None

def render_pdf(html: str) -> bytes | None:
    return _weasy_pdf(html) or _browser_pdf(html)
