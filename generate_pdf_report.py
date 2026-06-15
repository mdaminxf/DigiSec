#!/usr/bin/env python3
"""
DFIR Executive PDF Report Generator
Uses WeasyPrint to render styled HTML → PDF.
Call generate_report(content_dict, output_path) from other scripts,
or run directly to regenerate the baseline memory analysis report.
"""

import datetime
from pathlib import Path

try:
    from weasyprint import HTML, CSS
except ImportError:
    raise SystemExit("weasyprint not installed. Run: pip3 install weasyprint")


# ── Brand / Style ─────────────────────────────────────────────────────────────

CSS_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Roboto+Mono:wght@400;600&display=swap');

@page {
    size: A4;
    margin: 0;
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Inter', sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-right: 2cm;
        margin-bottom: 0.6cm;
    }
    @bottom-left {
        content: "CONFIDENTIAL — DFIR INTERNAL USE ONLY";
        font-family: 'Inter', sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-left: 2cm;
        margin-bottom: 0.6cm;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
    font-size: 9.5pt;
    color: #1f2937;
    background: #ffffff;
    line-height: 1.55;
}

/* ── Cover / Header ── */
.cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 60%, #1d4ed8 100%);
    color: white;
    padding: 2.8cm 2.2cm 2cm 2.2cm;
    page-break-after: always;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.cover-top { }

.org-tag {
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #93c5fd;
    margin-bottom: 0.5cm;
}

.report-type {
    font-size: 10pt;
    font-weight: 400;
    color: #bfdbfe;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 0.3cm;
}

.cover h1 {
    font-size: 28pt;
    font-weight: 700;
    line-height: 1.15;
    color: #ffffff;
    margin-bottom: 0.4cm;
}

.cover-subtitle {
    font-size: 13pt;
    font-weight: 300;
    color: #bfdbfe;
    margin-bottom: 1cm;
}

.cover-divider {
    width: 60px;
    height: 4px;
    background: #3b82f6;
    border-radius: 2px;
    margin: 0.6cm 0 1cm 0;
}

.cover-meta {
    display: table;
    border-collapse: collapse;
    width: 100%;
    margin-top: 0.6cm;
}
.cover-meta-row { display: table-row; }
.cover-meta-label {
    display: table-cell;
    font-size: 8pt;
    font-weight: 600;
    color: #93c5fd;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.12cm 0.6cm 0.12cm 0;
    white-space: nowrap;
    width: 3cm;
}
.cover-meta-value {
    display: table-cell;
    font-size: 9pt;
    color: #e0f2fe;
    padding: 0.12cm 0;
}

.cover-bottom {
    border-top: 1px solid rgba(255,255,255,0.15);
    padding-top: 0.4cm;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
}
.cover-classification {
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #fbbf24;
    text-transform: uppercase;
}
.cover-date {
    font-size: 8pt;
    color: #93c5fd;
}

/* ── Page header stripe ── */
.page-header {
    background: #0f172a;
    color: white;
    padding: 0.35cm 2.2cm;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.page-header-title {
    font-size: 8.5pt;
    font-weight: 600;
    letter-spacing: 0.05em;
    color: #93c5fd;
}
.page-header-case {
    font-size: 8pt;
    color: #6b7280;
}

/* ── Content area ── */
.content {
    padding: 0.8cm 2.2cm 1.5cm 2.2cm;
}

/* ── Section headings ── */
h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0.8cm;
    margin-bottom: 0.3cm;
    padding-bottom: 0.15cm;
    border-bottom: 2.5px solid #1d4ed8;
    display: flex;
    align-items: center;
    gap: 0.3cm;
}
h2 .section-num {
    background: #1d4ed8;
    color: white;
    font-size: 9pt;
    font-weight: 700;
    padding: 0.05cm 0.22cm;
    border-radius: 3px;
    min-width: 0.7cm;
    text-align: center;
}

h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e3a5f;
    margin-top: 0.5cm;
    margin-bottom: 0.2cm;
}

p { margin-bottom: 0.25cm; }

/* ── Executive Summary box ── */
.exec-summary {
    background: #eff6ff;
    border-left: 4px solid #1d4ed8;
    border-radius: 0 6px 6px 0;
    padding: 0.4cm 0.6cm;
    margin: 0.3cm 0 0.5cm 0;
}
.exec-summary p { margin-bottom: 0.15cm; font-size: 9.5pt; }
.exec-summary p:last-child { margin-bottom: 0; }

/* ── Alert boxes ── */
.alert {
    border-radius: 5px;
    padding: 0.3cm 0.5cm;
    margin: 0.3cm 0;
    font-size: 9pt;
}
.alert-red    { background: #fef2f2; border-left: 4px solid #dc2626; }
.alert-orange { background: #fff7ed; border-left: 4px solid #f97316; }
.alert-green  { background: #f0fdf4; border-left: 4px solid #16a34a; }
.alert-blue   { background: #eff6ff; border-left: 4px solid #2563eb; }

.alert-title {
    font-weight: 700;
    font-size: 9pt;
    margin-bottom: 0.1cm;
}
.alert-red    .alert-title { color: #dc2626; }
.alert-orange .alert-title { color: #c2410c; }
.alert-green  .alert-title { color: #15803d; }
.alert-blue   .alert-title { color: #1d4ed8; }

/* ── Tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.25cm 0 0.5cm 0;
    font-size: 8.8pt;
}
thead tr {
    background: #1e3a5f;
    color: white;
}
thead th {
    padding: 0.18cm 0.28cm;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
tbody tr:nth-child(even) { background: #f8fafc; }
tbody tr:nth-child(odd)  { background: #ffffff; }
tbody td {
    padding: 0.15cm 0.28cm;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}
tbody tr:hover { background: #eff6ff; }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 0.04cm 0.2cm;
    border-radius: 3px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.badge-critical { background: #7f1d1d; color: #fecaca; }
.badge-high     { background: #dc2626; color: #ffffff; }
.badge-medium   { background: #f97316; color: #ffffff; }
.badge-low      { background: #2563eb; color: #ffffff; }
.badge-info     { background: #6b7280; color: #ffffff; }
.badge-benign   { background: #16a34a; color: #ffffff; }

/* ── Code / mono ── */
code, .mono {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 8pt;
    background: #f1f5f9;
    padding: 0.02cm 0.1cm;
    border-radius: 3px;
    color: #0f172a;
}
.code-block {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 7.8pt;
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.35cm 0.45cm;
    border-radius: 6px;
    margin: 0.2cm 0 0.4cm 0;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
}
.code-block .hl  { color: #fbbf24; font-weight: 600; }
.code-block .red { color: #f87171; }
.code-block .grn { color: #86efac; }
.code-block .blu { color: #93c5fd; }

/* ── Process tree ── */
.proc-tree {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 8pt;
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.35cm 0.45cm;
    border-radius: 6px;
    margin: 0.2cm 0 0.4cm 0;
    line-height: 1.8;
}
.proc-tree .suspicious { color: #f87171; font-weight: 600; }
.proc-tree .benign     { color: #86efac; }
.proc-tree .neutral    { color: #93c5fd; }

/* ── Metric cards ── */
.metric-row {
    display: flex;
    gap: 0.3cm;
    margin: 0.3cm 0;
}
.metric-card {
    flex: 1;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-top: 3px solid #1d4ed8;
    border-radius: 5px;
    padding: 0.3cm 0.4cm;
    text-align: center;
}
.metric-card.red-top  { border-top-color: #dc2626; }
.metric-card.orange-top { border-top-color: #f97316; }
.metric-card.green-top  { border-top-color: #16a34a; }
.metric-number {
    font-size: 20pt;
    font-weight: 700;
    color: #0f172a;
    line-height: 1.1;
}
.metric-label {
    font-size: 7.5pt;
    font-weight: 600;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-top: 0.05cm;
}

/* ── Timeline ── */
.timeline { margin: 0.3cm 0; }
.tl-entry {
    display: flex;
    gap: 0.4cm;
    margin-bottom: 0.2cm;
    align-items: flex-start;
}
.tl-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #1d4ed8;
    margin-top: 0.1cm;
    flex-shrink: 0;
}
.tl-dot.red    { background: #dc2626; }
.tl-dot.orange { background: #f97316; }
.tl-dot.green  { background: #16a34a; }
.tl-time {
    font-family: 'Roboto Mono', monospace;
    font-size: 8pt;
    color: #4b5563;
    white-space: nowrap;
    flex-shrink: 0;
    width: 4.5cm;
}
.tl-text { font-size: 9pt; }

/* ── Footer note ── */
.footer-note {
    margin-top: 0.8cm;
    padding-top: 0.3cm;
    border-top: 1px solid #e5e7eb;
    font-size: 7.5pt;
    color: #9ca3af;
}

.page-break { page-break-before: always; }
"""


def build_html(data: dict) -> str:
    case_id    = data.get("case_id", "SRL-001")
    client     = data.get("client", "Stark Research Labs")
    prepared   = data.get("prepared_by", "DFIR Consulting Team")
    date_str   = data.get("date", datetime.datetime.utcnow().strftime("%Y-%m-%d"))
    title      = data.get("title", "DFIR Analysis Report")
    subtitle   = data.get("subtitle", "")
    body_html  = data.get("body_html", "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>{CSS_STYLE}</style>
</head>
<body>

<!-- ══ COVER PAGE ══ -->
<div class="cover">
  <div class="cover-top">
    <div class="org-tag">Digital Forensics &amp; Incident Response</div>
    <div class="report-type">Confidential Forensic Analysis</div>
    <h1>{title}</h1>
    <div class="cover-subtitle">{subtitle}</div>
    <div class="cover-divider"></div>
    <div class="cover-meta">
      <div class="cover-meta-row">
        <div class="cover-meta-label">Client</div>
        <div class="cover-meta-value">{client}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Case ID</div>
        <div class="cover-meta-value">{case_id}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Prepared By</div>
        <div class="cover-meta-value">{prepared}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Report Date</div>
        <div class="cover-meta-value">{date_str} UTC</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Classification</div>
        <div class="cover-meta-value" style="color:#fbbf24;font-weight:600;">CONFIDENTIAL — RESTRICTED DISTRIBUTION</div>
      </div>
    </div>
  </div>
  <div class="cover-bottom">
    <div class="cover-classification">&#9632; Confidential</div>
    <div class="cover-date">Report generated {date_str}</div>
  </div>
</div>

<!-- ══ BODY PAGES ══ -->
<div class="page-header">
  <div class="page-header-title">{title}</div>
  <div class="page-header-case">Case: {case_id} | {client}</div>
</div>
<div class="content">
{body_html}
<div class="footer-note">
  This report was produced as part of an active digital forensics investigation.
  All findings are based on evidence present at the time of analysis.
  Evidence integrity maintained per chain-of-custody protocol — source images not modified.
</div>
</div>

</body>
</html>"""


def generate_report(data: dict, output_path: str) -> str:
    html = build_html(data)
    HTML(string=html).write_pdf(
        output_path,
        stylesheets=[CSS(string="")],
        presentational_hints=True,
    )
    return output_path
