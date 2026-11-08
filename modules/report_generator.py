"""HTML and optional PDF report generation."""
from flask import render_template

DISCLAIMER = "Only scan systems you own or have explicit permission to assess. This report is an educational point-in-time assessment, not proof of exploitability or a substitute for a professional security review."

def render_report(scan):
    data = scan.result_json or {}
    return render_template("report.html", scan=scan, data=data, disclaimer=DISCLAIMER)

def render_pdf(html: str) -> bytes | None:
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except Exception:
        return None
