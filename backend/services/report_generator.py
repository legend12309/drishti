"""
DRISHTI — Professional PDF Security Report Generator
Generates comprehensive, branded PDF reports from scan findings using WeasyPrint.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.db.database import get_db

logger = logging.getLogger("drishti.report_generator")

# Try to import WeasyPrint - it requires GTK libraries which may not be available on Windows
try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
    FONT_CONFIG = FontConfiguration()
except (ImportError, OSError) as e:
    logger.warning("WeasyPrint not available (requires GTK libraries): %s", e)
    WEASYPRINT_AVAILABLE = False
    HTML = None
    CSS = None
    FONT_CONFIG = None

# Report template directory
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates", "reports")


class ReportGenerator:
    """Generates professional PDF security assessment reports."""
    
    def __init__(self):
        self.jinja_env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
    
    async def generate_report(
        self,
        workflow_id: str,
        output_path: str,
        include_ai_analysis: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a professional PDF report for a completed workflow.
        
        Returns:
            Dict with status, file_path, file_size, and metadata
        """
        if not WEASYPRINT_AVAILABLE:
            return {
                "status": "error",
                "error": "PDF generation unavailable - WeasyPrint requires GTK libraries. Install GTK on the host system to enable PDF generation."
            }
        
        try:
            # Gather all data needed for the report
            report_data = await self._collect_report_data(workflow_id)
            
            if not report_data:
                return {
                    "status": "error",
                    "error": "Workflow not found or no data available"
                }
            
            # Generate AI analysis if requested and available
            ai_analysis = None
            if include_ai_analysis:
                ai_analysis = await self._generate_ai_analysis(report_data)
            
            # Render HTML template
            html_content = self._render_html(report_data, ai_analysis)
            
            # Generate PDF
            file_size = await self._generate_pdf(html_content, output_path)
            
            # Save report metadata to database
            await self._save_report_metadata(workflow_id, output_path, file_size, report_data)
            
            return {
                "status": "success",
                "file_path": output_path,
                "file_size": file_size,
                "report_id": f"rpt-{workflow_id}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            
        except Exception as e:
            logger.exception("PDF report generation failed for %s", workflow_id)
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _collect_report_data(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Collect all scan data needed for the report."""
        async with get_db() as db:
            # Get workflow/scan record
            async with db.execute(
                "SELECT * FROM scans WHERE id = ?", (workflow_id,)
            ) as cursor:
                scan = await cursor.fetchone()
                if not scan:
                    return None
                scan = dict(scan)
            
            # Get stage records
            async with db.execute(
                "SELECT * FROM scan_stages WHERE scan_id = ? ORDER BY id ASC",
                (workflow_id,)
            ) as cursor:
                stages = [dict(r) for r in await cursor.fetchall()]
            
            # Get all findings
            async with db.execute(
                "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY risk DESC, id ASC",
                (workflow_id,)
            ) as cursor:
                findings = [dict(r) for r in await cursor.fetchall()]
            
            # Get vulnerability intelligence if available
            async with db.execute(
                "SELECT * FROM vulnerability_findings WHERE scan_id = ?",
                (workflow_id,)
            ) as cursor:
                vuln_intel = [dict(r) for r in await cursor.fetchall()]
            
            # Get attack graph if available
            async with db.execute(
                "SELECT * FROM graph_snapshots WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
                (workflow_id,)
            ) as cursor:
                graph = await cursor.fetchone()
                graph_data = dict(graph) if graph else None
            
            # Get risk assessment if available
            async with db.execute(
                "SELECT * FROM risk_assessments WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1",
                (workflow_id,)
            ) as cursor:
                risk = await cursor.fetchone()
                risk_data = dict(risk) if risk else None
            
            # Get authorization info
            auth = None
            if scan.get("authorization_id"):
                async with db.execute(
                    "SELECT * FROM authorizations WHERE id = ?",
                    (scan["authorization_id"],)
                ) as cursor:
                    auth_row = await cursor.fetchone()
                    if auth_row:
                        auth = dict(auth_row)
            
            return {
                "scan": scan,
                "stages": stages,
                "findings": findings,
                "vuln_intel": vuln_intel,
                "graph": graph_data,
                "risk_assessment": risk_data,
                "authorization": auth,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
    
    def _render_html(self, report_data: Dict[str, Any], ai_analysis: Optional[Dict] = None) -> str:
        """Render the HTML template with report data."""
        template = self.jinja_env.get_template("security_report.html")
        
        scan = report_data["scan"]
        stages = report_data["stages"]
        findings = report_data["findings"]
        
        # Calculate severity distribution
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            risk = f.get("risk", "").upper()
            if risk in severity_counts:
                severity_counts[risk] += 1
            elif risk:
                severity_counts["INFO"] += 1
        
        # Parse requested scanners
        import json
        requested_scanners = []
        try:
            requested_scanners = json.loads(scan.get("requested_scanners") or "[]")
        except Exception:
            pass
        
        context = {
            "report": {
                "id": f"DRS-{scan['id']}",
                "title": "Security Assessment Report",
                "target": scan.get("target", "Unknown"),
                "scope": scan.get("scope", "FULL_ACTIVE"),
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "workflow_id": scan["id"],
            },
            "authorization": report_data.get("authorization"),
            "scan": scan,
            "stages": stages,
            "findings": findings,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "requested_scanners": requested_scanners,
            "ai_analysis": ai_analysis,
            "risk_assessment": report_data.get("risk_assessment"),
            "graph": report_data.get("graph"),
            "vuln_intel": report_data.get("vuln_intel"),
        }
        
        return template.render(**context)
    
    async def _generate_pdf(self, html_content: str, output_path: str) -> int:
        """Generate PDF from HTML content using WeasyPrint."""
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Create PDF with professional styling
        font_config = FontConfiguration()
        html_doc = HTML(string=html_content, base_url=".")
        
        # Add custom CSS for professional appearance
        css = CSS(string=self._get_report_css())
        
        html_doc.write_pdf(output_path, stylesheets=[css], font_config=font_config)
        
        return os.path.getsize(output_path)
    
    def _get_report_css(self) -> str:
        """Professional CSS for the PDF report."""
        return """
        @page {
            size: A4;
            margin: 2.5cm 2cm;
            @top-center {
                content: "DRISHTI Security Assessment Report";
                font-size: 9pt;
                color: #6C4CF1;
                font-family: "DejaVu Sans", sans-serif;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #77758E;
                font-family: "DejaVu Sans", sans-serif;
            }
        }
        
        * {
            box-sizing: border-box;
        }
        
        body {
            font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #22213A;
            background: white;
        }
        
        .report-header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 3px solid #6C4CF1;
            margin-bottom: 30px;
        }
        
        .report-header .logo {
            font-size: 28pt;
            font-weight: bold;
            color: #6C4CF1;
            margin-bottom: 10px;
        }
        
        .report-header .subtitle {
            font-size: 14pt;
            color: #77758E;
        }
        
        .report-meta {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 30px;
            padding: 20px;
            background: #F4F1FF;
            border-radius: 8px;
            border: 1px solid #E8E4F2;
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        
        .meta-label {
            font-size: 9pt;
            font-weight: bold;
            color: #77758E;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .meta-value {
            font-size: 11pt;
            color: #22213A;
            font-family: monospace;
        }
        
        .section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }
        
        .section-title {
            font-size: 14pt;
            font-weight: bold;
            color: #22213A;
            border-bottom: 2px solid #6C4CF1;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }
        
        .stage-table, .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 9pt;
        }
        
        .stage-table th, .findings-table th {
            background: #6C4CF1;
            color: white;
            padding: 10px 8px;
            text-align: left;
            font-weight: bold;
        }
        
        .stage-table td, .findings-table td {
            padding: 8px;
            border-bottom: 1px solid #E8E4F2;
        }
        
        .stage-table tr:nth-child(even), .findings-table tr:nth-child(even) {
            background: #FAF9FF;
        }
        
        .severity-critical { background: #FFF0F1; color: #DC4655; font-weight: bold; }
        .severity-high { background: #FFF7E8; color: #C78A27; font-weight: bold; }
        .severity-medium { background: #EDE8FF; color: #6C4CF1; }
        .severity-low { background: #EAF8F1; color: #299B75; }
        .severity-info { background: #F0F0F0; color: #5279D9; }
        
        .status-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 8pt;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-completed { background: #EAF8F1; color: #299B75; }
        .status-failed { background: #FFF0F1; color: #DC4655; }
        .status-skipped { background: #F0F0F0; color: #77758E; }
        .status-running { background: #EAE4FF; color: #6C4CF1; }
        .status-queued { background: #FFF7E8; color: #C78A27; }
        
        .severity-bar {
            display: flex;
            gap: 8px;
            margin: 15px 0;
        }
        
        .severity-box {
            flex: 1;
            padding: 12px;
            text-align: center;
            border-radius: 6px;
        }
        
        .severity-box.critical { background: #DC4655; color: white; }
        .severity-box.high { background: #C78A27; color: white; }
        .severity-box.medium { background: #6C4CF1; color: white; }
        .severity-box.low { background: #299B75; color: white; }
        .severity-box.info { background: #5279D9; color: white; }
        
        .severity-box .count {
            font-size: 24pt;
            font-weight: bold;
            display: block;
        }
        
        .severity-box .label {
            font-size: 9pt;
            text-transform: uppercase;
            opacity: 0.9;
        }
        
        .ai-section {
            background: #F3F0FF;
            border: 1px solid #E8E4F2;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .ai-section h4 {
            color: #6C4CF1;
            margin-top: 0;
        }
        
        .ai-section .ai-label {
            font-size: 8pt;
            color: #6C4CF1;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
            display: inline-block;
        }
        
        .finding-detail {
            margin-bottom: 20px;
            padding: 15px;
            background: #FAF9FF;
            border: 1px solid #E8E4F2;
            border-radius: 6px;
            page-break-inside: avoid;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-size: 12pt;
            font-weight: bold;
            color: #22213A;
        }
        
        .finding-meta {
            display: flex;
            gap: 15px;
            font-size: 9pt;
            color: #77758E;
            margin-top: 5px;
        }
        
        .finding-evidence {
            background: #F4F4F4;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 8pt;
            overflow-x: auto;
            margin-top: 10px;
        }
        
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #E8E4F2;
            text-align: center;
            font-size: 9pt;
            color: #77758E;
        }
        
        @media print {
            .no-print { display: none; }
        }
        """
    
    async def _generate_ai_analysis(self, report_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate AI-assisted analysis of findings."""
        try:
            from backend.services.intelligence_explainer import generate_assessment_summary
            
            findings = report_data.get("findings", [])
            scan = report_data.get("scan", {})
            
            if not findings:
                return {
                    "executive_summary": "No security findings were detected during this assessment.",
                    "risk_summary": "The assessment did not identify any vulnerabilities within the authorized scope.",
                    "top_findings": [],
                    "recommendations": ["No specific remediation actions required."],
                    "limitations": ["Assessment limited to authorized scope and scanner coverage."],
                }
            
            # Format findings for AI
            formatted_findings = []
            for f in findings[:20]:  # Limit to top 20 for token efficiency
                formatted_findings.append({
                    "title": f.get("title", f.get("host", "Unknown")),
                    "severity": f.get("risk", "UNKNOWN"),
                    "description": f.get("description", f.get("detail", "No description available")),
                    "target": f.get("host", f.get("target", "Unknown")),
                    "port": f.get("port"),
                    "cve": f.get("cve_id", f.get("cve")),
                    "evidence": f.get("evidence", f.get("raw_output", ""))[:500],
                })
            
            summary = await generate_assessment_summary(
                target=scan.get("target", "Unknown"),
                findings=formatted_findings,
                scope=scan.get("scope", "FULL_ACTIVE"),
            )
            
            return summary
            
        except Exception as e:
            logger.warning("AI analysis generation failed: %s", e)
            return None
    
    async def _save_report_metadata(
        self,
        workflow_id: str,
        file_path: str,
        file_size: int,
        report_data: Dict[str, Any],
    ) -> None:
        """Save report metadata to database."""
        try:
            async with get_db() as db:
                await db.execute(
                    """
                    INSERT INTO scan_reports (
                        scan_id, file_path, file_size, generated_at, status
                    ) VALUES ($1, $2, $3, $4, 'generated')
                    ON CONFLICT(scan_id) DO UPDATE SET
                        file_path = excluded.file_path,
                        file_size = excluded.file_size,
                        generated_at = excluded.generated_at,
                        status = excluded.status
                    """,
                    (
                        workflow_id,
                        file_path,
                        file_size,
                        datetime.now(timezone.utc).isoformat(),
                    )
                )
                await db.commit()
        except Exception as e:
            logger.warning("Failed to save report metadata: %s", e)


# Global instance
report_generator = ReportGenerator()


async def generate_security_report(workflow_id: str, output_dir: str = "/tmp/drishti_reports") -> Dict[str, Any]:
    """Convenience function to generate a security report."""
    output_path = os.path.join(output_dir, f"drishti-report-{workflow_id}.pdf")
    return await report_generator.generate_report(workflow_id, output_path)