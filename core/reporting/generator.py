import os
import json
from typing import Dict, Any, List
from datetime import datetime
from core.models.finding import Finding
from core.workspace import get_workspace, get_report_path, load_json

try:
    from generate_pdf_report import generate_report
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


class ReportGenerator:
    """Generates executive and technical reports for DFIR investigations."""

    def __init__(self, case_id: str, case_type: str = "", description: str = ""):
        self.case_id = case_id
        self.case_type = case_type
        self.description = description

    def _build_executive_html(self, findings: List[Finding], summary: Dict[str, Any]) -> str:
        """Build the body HTML for the executive PDF report."""
        html = []

        # Executive Summary
        html.append('<h2><span class="section-num">01</span> Executive Summary</h2>')
        html.append('<div class="exec-summary">')
        html.append(f'  <p>Case <strong>{self.case_id}</strong> — {self.case_type.replace("_", " ").title()}</p>')
        html.append(f'  <p>{self.description}</p>')
        html.append('</div>')

        # Metrics
        html.append('<div class="metric-row">')
        html.append(f'  <div class="metric-card red-top"><div class="metric-number">{len(findings)}</div><div class="metric-label">Total Findings</div></div>')
        completed = summary.get("phases_completed", 0)
        total_phases = summary.get("phases_total", 0)
        html.append(f'  <div class="metric-card blue-top"><div class="metric-number">{completed}/{total_phases}</div><div class="metric-label">Phases Completed</div></div>')
        coverage = summary.get("coverage", {})
        cov_pct = coverage.get("coverage_pct", 0)
        html.append(f'  <div class="metric-card green-top"><div class="metric-number">{cov_pct}%</div><div class="metric-label">Objective Coverage</div></div>')
        html.append('</div>')

        # Findings
        html.append('<h2><span class="section-num">02</span> Findings</h2>')
        if not findings:
            html.append('<p>No findings were identified during this investigation.</p>')
        for i, f in enumerate(findings, 1):
            severity_class = "alert-red" if f.severity in ("critical", "high") else "alert-orange" if f.severity == "medium" else "alert-blue"
            html.append(f'<div class="alert {severity_class}">')
            html.append(f'  <div class="alert-title">&#9888; {f.severity.upper()} — {f.title}</div>')
            html.append(f'  {f.description}')
            html.append('</div>')

            if f.evidence:
                html.append('<table>')
                html.append('  <thead><tr><th>Source</th><th>Artifact</th><th>Confidence</th></tr></thead>')
                html.append('  <tbody>')
                for ev in f.evidence:
                    html.append(f'    <tr><td><code>{ev.source}</code></td><td>{ev.artifact}</td><td>{ev.confidence:.0%}</td></tr>')
                html.append('  </tbody></table>')

        # Evidence Gaps
        unsatisfied = coverage.get("unsatisfied", [])
        if unsatisfied:
            html.append('<h2><span class="section-num">03</span> Evidence Gaps</h2>')
            html.append('<div class="alert alert-orange">')
            html.append('  <div class="alert-title">Unsatisfied Objectives</div>')
            html.append('  <ul>')
            for gap in unsatisfied:
                html.append(f'    <li style="margin-left:20px">{gap}</li>')
            html.append('  </ul>')
            html.append('</div>')

        # Errors
        errors = summary.get("errors", [])
        if errors:
            html.append('<h2><span class="section-num">04</span> Execution Errors</h2>')
            html.append('<div class="alert alert-red">')
            html.append('  <div class="alert-title">Errors Encountered During Investigation</div>')
            html.append('  <ul>')
            for err in errors:
                html.append(f'    <li style="margin-left:20px"><code>{err}</code></li>')
            html.append('  </ul>')
            html.append('</div>')

        return "\n".join(html)

    def generate_executive_pdf(self, findings: List[Finding], summary: Dict[str, Any]) -> str:
        """Generate the executive PDF report using WeasyPrint."""
        if not HAS_PDF:
            return "WeasyPrint not installed. PDF generation skipped."

        body_html = self._build_executive_html(findings, summary)
        report_data = {
            "title": f"DFIR Investigation Report",
            "subtitle": self.case_type.replace("_", " ").title(),
            "case_id": self.case_id,
            "client": "Internal Security Team",
            "body_html": body_html,
        }

        output_path = get_report_path(self.case_id, "pdf")
        generate_report(report_data, output_path)
        return output_path

    def generate_technical_json(self, findings: List[Finding], summary: Dict[str, Any]) -> str:
        """Generate the technical JSON report with full detail."""
        report = {
            "report_type": "technical",
            "case_id": self.case_id,
            "case_type": self.case_type,
            "description": self.description,
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "findings": [f.model_dump() for f in findings],
            "evidence_graph": load_json(self.case_id, "graph", "evidence_graph.json"),
            "timeline": load_json(self.case_id, "timelines", "attack_timeline.json"),
        }

        output_path = get_report_path(self.case_id, "json")
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return output_path

    def generate_all(self, findings: List[Finding], summary: Dict[str, Any]) -> Dict[str, str]:
        """Generate both executive PDF and technical JSON reports."""
        paths = {}
        try:
            paths["pdf"] = self.generate_executive_pdf(findings, summary)
        except Exception as e:
            paths["pdf_error"] = str(e)
        try:
            paths["json"] = self.generate_technical_json(findings, summary)
        except Exception as e:
            paths["json_error"] = str(e)
        return paths
