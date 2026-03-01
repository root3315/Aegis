"""
Report generation module for Aegis security scanner.

Generates scan reports in multiple formats (JSON, HTML, Markdown).
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum, auto

from .scanner import ScanResult, Vulnerability, PortResult, PortState, VulnerabilitySeverity
from .utils import ensure_directory, get_timestamp


class ReportFormat(Enum):
    """Supported report output formats."""
    JSON = auto()
    HTML = auto()
    MARKDOWN = auto()
    TEXT = auto()


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.
    
    Supports JSON, HTML, Markdown, and plain text output.
    """
    
    def __init__(self, output_dir: str = "./reports") -> None:
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for report output
        """
        self.output_dir = ensure_directory(output_dir)
    
    def generate(
        self,
        result: ScanResult,
        format: ReportFormat = ReportFormat.JSON,
        filename: Optional[str] = None,
    ) -> str:
        """
        Generate report in specified format.
        
        Args:
            result: Scan result data
            format: Output format
            filename: Optional custom filename
            
        Returns:
            Path to generated report file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aegis_scan_{timestamp}"
        
        if format == ReportFormat.JSON:
            return self._generate_json(result, filename)
        elif format == ReportFormat.HTML:
            return self._generate_html(result, filename)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(result, filename)
        elif format == ReportFormat.TEXT:
            return self._generate_text(result, filename)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_json(self, result: ScanResult, filename: str) -> str:
        """Generate JSON format report."""
        filepath = self.output_dir / f"{filename}.json"
        
        report_data = {
            "report_metadata": {
                "tool": "Aegis Security Scanner",
                "version": "1.0.0",
                "generated_at": get_timestamp(),
                "format": "JSON",
            },
            "scan_result": result.to_dict(),
        }
        
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2)
        
        return str(filepath)
    
    def _generate_html(self, result: ScanResult, filename: str) -> str:
        """Generate HTML format report."""
        filepath = self.output_dir / f"{filename}.html"
        
        # Calculate severity counts
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for vuln in result.vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis Security Scan Report - {result.target}</title>
    <style>
        :root {{
            --primary: #1a365d;
            --secondary: #2c5282;
            --success: #38a169;
            --warning: #d69e2e;
            --danger: #e53e3e;
            --critical: #742a2a;
            --light: #f7fafc;
            --dark: #1a202c;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: var(--dark);
            background: var(--light);
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        header p {{ opacity: 0.9; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card h3 {{ font-size: 0.875rem; color: #718096; margin-bottom: 0.5rem; }}
        .summary-card .value {{ font-size: 2rem; font-weight: bold; color: var(--primary); }}
        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--danger); }}
        .severity-medium {{ color: var(--warning); }}
        .severity-low {{ color: var(--success); }}
        section {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
        }}
        section h2 {{
            color: var(--primary);
            border-bottom: 2px solid var(--secondary);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{ background: var(--light); font-weight: 600; }}
        tr:hover {{ background: var(--light); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-open {{ background: #c6f6d5; color: #22543d; }}
        .badge-closed {{ background: #fed7d7; color: #742a2a; }}
        .badge-filtered {{ background: #feebc8; color: #744210; }}
        .badge-critical {{ background: #feb2b2; color: #742a2a; }}
        .badge-high {{ background: #fc8181; color: #742a2a; }}
        .badge-medium {{ background: #f6e05e; color: #744210; }}
        .badge-low {{ background: #9ae6b4; color: #22543d; }}
        .vuln-item {{
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        .vuln-title {{ font-weight: 600; color: var(--primary); }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: #718096;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Aegis Security Scan Report</h1>
            <p>Target: <strong>{result.target}</strong> ({result.target_ip})</p>
            <p>Scan Duration: {result.duration:.2f}s | Generated: {result.scan_end}</p>
        </header>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Ports Scanned</h3>
                <div class="value">{result.ports_scanned}</div>
            </div>
            <div class="summary-card">
                <h3>Open Ports</h3>
                <div class="value">{len(result.open_ports)}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <div class="value">{len(result.vulnerabilities)}</div>
            </div>
            <div class="summary-card">
                <h3>Services Detected</h3>
                <div class="value">{len(result.services)}</div>
            </div>
        </div>
        
        <section>
            <h2>Vulnerability Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Critical</h3>
                    <div class="value severity-critical">{severity_counts['CRITICAL']}</div>
                </div>
                <div class="summary-card">
                    <h3>High</h3>
                    <div class="value severity-high">{severity_counts['HIGH']}</div>
                </div>
                <div class="summary-card">
                    <h3>Medium</h3>
                    <div class="value severity-medium">{severity_counts['MEDIUM']}</div>
                </div>
                <div class="summary-card">
                    <h3>Low</h3>
                    <div class="value severity-low">{severity_counts['LOW']}</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Detected Vulnerabilities</h2>
            {self._generate_vulnerability_html(result.vulnerabilities)}
        </section>
        
        <section>
            <h2>Open Ports & Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>State</th>
                        <th>Response Time</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_ports_html(result.open_ports)}
                </tbody>
            </table>
        </section>
        
        <footer>
            <p>Generated by Aegis Security Scanner v1.0.0</p>
            <p>Report generated at {get_timestamp()}</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(filepath, "w") as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _generate_vulnerability_html(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate HTML for vulnerability list."""
        if not vulnerabilities:
            return "<p>No vulnerabilities detected.</p>"
        
        html = ""
        for vuln in vulnerabilities:
            badge_class = f"badge-{vuln.severity.value.lower()}"
            html += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <span class="vuln-title">{vuln.name}</span>
                    <span class="badge {badge_class}">{vuln.severity.value}</span>
                </div>
                <p><strong>ID:</strong> {vuln.id} | <strong>Port:</strong> {vuln.affected_port} ({vuln.affected_service})</p>
                <p>{vuln.description}</p>
                {f'<p><strong>CVE:</strong> {vuln.cve_id} | <strong>CVSS:</strong> {vuln.cvss_score}</p>' if vuln.cve_id else ''}
                <p><strong>Remediation:</strong> {vuln.remediation}</p>
            </div>
            """
        return html
    
    def _generate_ports_html(self, ports: List[PortResult]) -> str:
        """Generate HTML for ports table."""
        html = ""
        for port in ports:
            state_class = f"badge-{port.state.name.lower()}"
            html += f"""
            <tr>
                <td>{port.port}</td>
                <td>{port.protocol.upper()}</td>
                <td>{port.service or 'Unknown'}</td>
                <td><span class="badge {state_class}">{port.state.name}</span></td>
                <td>{port.response_time * 1000:.1f}ms</td>
            </tr>
            """
        return html
    
    def _generate_markdown(self, result: ScanResult, filename: str) -> str:
        """Generate Markdown format report."""
        filepath = self.output_dir / f"{filename}.md"
        
        md_content = f"""# Aegis Security Scan Report

## Scan Information

| Property | Value |
|----------|-------|
| **Target** | {result.target} |
| **IP Address** | {result.target_ip} |
| **Scan Started** | {result.scan_start} |
| **Scan Completed** | {result.scan_end} |
| **Duration** | {result.duration:.2f}s |
| **Ports Scanned** | {result.ports_scanned} |

## Summary

- **Open Ports:** {len(result.open_ports)}
- **Closed Ports:** {len(result.closed_ports)}
- **Filtered Ports:** {len(result.filtered_ports)}
- **Vulnerabilities Found:** {len(result.vulnerabilities)}

## Vulnerabilities

"""
        
        if result.vulnerabilities:
            severity_counts = {}
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            md_content += "### Severity Distribution\n\n"
            for sev, count in severity_counts.items():
                md_content += f"- **{sev}:** {count}\n"
            md_content += "\n### Details\n\n"
            
            for vuln in result.vulnerabilities:
                md_content += f"""#### [{vuln.severity.value}] {vuln.name}

- **ID:** {vuln.id}
- **Port:** {vuln.affected_port} ({vuln.affected_service})
"""
                if vuln.cve_id:
                    md_content += f"- **CVE:** {vuln.cve_id}\n"
                if vuln.cvss_score:
                    md_content += f"- **CVSS:** {vuln.cvss_score}\n"
                
                md_content += f"""
**Description:** {vuln.description}

**Remediation:** {vuln.remediation}

---

"""
        else:
            md_content += "*No vulnerabilities detected.*\n\n"
        
        md_content += "## Open Ports\n\n"
        
        if result.open_ports:
            md_content += "| Port | Protocol | Service | State | Response Time |\n"
            md_content += "|------|----------|---------|-------|---------------|\n"
            for port in result.open_ports:
                response_ms = port.response_time * 1000
                md_content += f"| {port.port} | {port.protocol} | {port.service or 'Unknown'} | {port.state.name} | {response_ms:.1f}ms |\n"
        else:
            md_content += "*No open ports detected.*\n"
        
        md_content += f"\n---\n\n*Generated by Aegis Security Scanner v1.0.0 at {get_timestamp()}*\n"
        
        with open(filepath, "w") as f:
            f.write(md_content)
        
        return str(filepath)
    
    def _generate_text(self, result: ScanResult, filename: str) -> str:
        """Generate plain text format report."""
        filepath = self.output_dir / f"{filename}.txt"
        
        lines = [
            "=" * 70,
            "AEGIS SECURITY SCAN REPORT",
            "=" * 70,
            "",
            f"Target: {result.target} ({result.target_ip})",
            f"Scan Duration: {result.duration:.2f}s",
            f"Generated: {result.scan_end}",
            "",
            "-" * 70,
            "SUMMARY",
            "-" * 70,
            f"Ports Scanned: {result.ports_scanned}",
            f"Open Ports: {len(result.open_ports)}",
            f"Closed Ports: {len(result.closed_ports)}",
            f"Filtered Ports: {len(result.filtered_ports)}",
            f"Vulnerabilities: {len(result.vulnerabilities)}",
            "",
        ]
        
        if result.vulnerabilities:
            lines.extend([
                "-" * 70,
                "VULNERABILITIES",
                "-" * 70,
            ])
            for vuln in result.vulnerabilities:
                lines.append(f"[{vuln.severity.value}] {vuln.name}")
                lines.append(f"  Port: {vuln.affected_port} ({vuln.affected_service})")
                lines.append(f"  Description: {vuln.description}")
                if vuln.cve_id:
                    lines.append(f"  CVE: {vuln.cve_id}")
                lines.append(f"  Remediation: {vuln.remediation}")
                lines.append("")
        
        lines.extend([
            "-" * 70,
            "OPEN PORTS",
            "-" * 70,
        ])
        
        if result.open_ports:
            for port in result.open_ports:
                service = port.service or "Unknown"
                lines.append(f"  {port.port}/tcp  {port.state.name:<10}  {service}")
        else:
            lines.append("  No open ports detected.")
        
        lines.extend([
            "",
            "=" * 70,
            f"Generated by Aegis Security Scanner v1.0.0",
            f"Report timestamp: {get_timestamp()}",
            "=" * 70,
        ])
        
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        
        return str(filepath)
