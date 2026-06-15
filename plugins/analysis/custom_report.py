from core.models import ToolResult
from core.registry import register_tool
from generate_pdf_report import generate_report
from core.workspace import get_report_path
import datetime
import os

@register_tool
def generate_custom_pdf_report(case_id: str, title: str, subtitle: str, body_html: str) -> ToolResult:
    """Generates an elegant, executive-level PDF forensic report from raw HTML and saves it to the workspace.
    
    Instead of outputting large forensic reports directly into the chat, you should 
    construct the report using HTML (including headings, tables, alerts, and metrics)
    and use this tool to compile it into a beautifully styled PDF document.
    
    Args:
        case_id: The identifier for the case (e.g., "SRL-2023-001")
        title: The main title of the report (e.g., "Executive DFIR Report")
        subtitle: A subtitle or description (e.g., "Fred Rocba IP Theft Investigation")
        body_html: The raw HTML content of the report body. Use standard HTML tags (<h2>, <h3>, <table>, <div class="alert alert-red">, etc.)
    """
    try:
        # Generate a safe filename
        safe_title = title.lower().replace(" ", "_").replace("/", "_")
        output_pdf = get_report_path(case_id, "pdf")
        # Ensure it has a custom name
        output_pdf = output_pdf.replace("report.pdf", f"{safe_title}.pdf")
        
        report_data = {
            "case_id": case_id,
            "client": "Internal Security Team",
            "prepared_by": "AI DFIR Agent",
            "date": datetime.datetime.utcnow().strftime("%Y-%m-%d"),
            "title": title,
            "subtitle": subtitle,
            "body_html": body_html,
        }
        
        pdf_path = generate_report(report_data, output_pdf)
        
        return ToolResult(
            tool_name="generate_custom_pdf_report",
            success=True,
            data=f"PDF Report successfully generated and saved to: {pdf_path}"
        )
    except Exception as e:
        return ToolResult(
            tool_name="generate_custom_pdf_report",
            success=False,
            errors=[f"Failed to generate PDF: {str(e)}"]
        )
