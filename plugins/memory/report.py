import os
from core.models import ToolResult
from core.registry import register_tool
from plugins.memory.triage import memory_triage
from generate_pdf_report import generate_report
from core.workspace import get_case_name, get_report_path

@register_tool
def generate_memory_report(memory_file: str) -> ToolResult:
    """Generates a comprehensive, executive-level PDF forensic report of a memory image, saving it directly to the case workspace."""
    case_name = get_case_name(memory_file)
    output_pdf = get_report_path(case_name, "pdf")

    triage_result = memory_triage(memory_file)
    data = triage_result.data
    findings = triage_result.findings
    
    html = []
    html.append(f"<h2><span class=\"section-num\">01</span> Executive Summary</h2>")
    html.append(f"<div class=\"exec-summary\">")
    html.append(f"  <p>Memory analysis performed on <code>{memory_file}</code>.</p>")
    html.append(f"</div>")

    html.append(f"<div class=\"metric-row\">")
    html.append(f"  <div class=\"metric-card red-top\">")
    html.append(f"    <div class=\"metric-number\">{data['high_risk_processes']}</div>")
    html.append(f"    <div class=\"metric-label\">High-Risk Processes</div>")
    html.append(f"  </div>")
    html.append(f"  <div class=\"metric-card blue-top\">")
    html.append(f"    <div class=\"metric-number\">{data['process_count']}</div>")
    html.append(f"    <div class=\"metric-label\">Total Processes</div>")
    html.append(f"  </div>")
    html.append(f"</div>")

    html.append(f"<h2><span class=\"section-num\">02</span> System Profile</h2>")
    html.append(f"<table>")
    html.append(f"  <thead><tr><th>Property</th><th>Value</th></tr></thead>")
    html.append(f"  <tbody>")
    html.append(f"    <tr><td>Memory Image</td><td><code>{os.path.basename(memory_file)}</code></td></tr>")
    html.append(f"    <tr><td>Operating System</td><td>{data['os']}</td></tr>")
    html.append(f"  </tbody>")
    html.append(f"</table>")

    html.append(f"<h2><span class=\"section-num\">03</span> Findings</h2>")
    for f in findings:
        html.append(f"<div class=\"alert alert-red\">")
        html.append(f"  <div class=\"alert-title\">&#9888; {f.severity.upper()} SEVERITY — {f.title}</div>")
        html.append(f"  {f.description}")
        html.append(f"</div>")
        
        html.append(f"<h3>Evidence Provenance</h3>")
        html.append(f"<table>")
        html.append(f"  <thead><tr><th>Source</th><th>Artifact</th><th>Confidence</th></tr></thead>")
        html.append(f"  <tbody>")
        for ev in f.evidence:
            html.append(f"    <tr><td><code>{ev.source}</code></td><td>{ev.artifact}</td><td>{ev.confidence}</td></tr>")
        html.append(f"  </tbody>")
        html.append(f"</table>")

    html.append(f"<h2><span class=\"section-num\">04</span> Recommended Next Steps</h2>")
    html.append(f"<ul>")
    html.append(f"  <li style=\"margin-left: 20px;\">Isolate the affected endpoint.</li>")
    html.append(f"  <li style=\"margin-left: 20px;\">Review the injected memory regions for payload extraction.</li>")
    html.append(f"  <li style=\"margin-left: 20px;\">Check firewall logs for the flagged external IPs.</li>")
    html.append(f"</ul>")
    
    body_html = "\n".join(html)

    report_data = {
        "title": "Automated Memory Analysis Report",
        "case_id": case_name.upper(),
        "client": "Internal Security Team",
        "body_html": body_html
    }

    pdf_path = generate_report(report_data, output_pdf)

    return ToolResult(
        tool_name="generate_memory_report",
        success=True,
        data=f"PDF Report successfully generated and saved to Workspace: {pdf_path}"
    )
