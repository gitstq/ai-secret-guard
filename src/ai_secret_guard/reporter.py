"""
Report generation module for scan results.
扫描结果报告生成模块。
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from .models import ScanResult, Finding, Severity, SecretType

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates various format reports from scan results.
    从扫描结果生成多种格式的报告。
    """
    
    def __init__(self, result: ScanResult):
        self.result = result
        
    def generate_json_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate JSON format report.
        生成JSON格式报告。
        """
        report = self.result.to_dict()
        report["generated_at"] = datetime.now().isoformat()
        report["tool_version"] = "1.0.0"
        
        json_output = json.dumps(report, indent=2, ensure_ascii=False)
        
        if output_path:
            Path(output_path).write_text(json_output, encoding='utf-8')
            logger.info(f"📄 JSON report saved to: {output_path}")
            
        return json_output
        
    def generate_html_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate HTML format report with styling.
        生成带样式的HTML格式报告。
        """
        html = self._build_html()
        
        if output_path:
            Path(output_path).write_text(html, encoding='utf-8')
            logger.info(f"🌐 HTML report saved to: {output_path}")
            
        return html
        
    def generate_console_report(self) -> str:
        """
        Generate console-friendly text report.
        生成适合控制台显示的文本报告。
        """
        lines = []
        lines.append("=" * 80)
        lines.append("🔒 AI Secret Guard - Scan Report")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"📁 Repository: {self.result.repository_path}")
        lines.append(f"📅 Scan Time: {self.result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"📊 Files Scanned: {self.result.files_scanned}")
        lines.append(f"⏭️  Files Skipped: {self.result.files_skipped}")
        lines.append("")
        
        # Summary
        lines.append("-" * 80)
        lines.append("📋 Summary")
        lines.append("-" * 80)
        lines.append(f"   🔴 Critical: {self.result.critical_count}")
        lines.append(f"   🟠 High:     {self.result.high_count}")
        lines.append(f"   🟡 Medium:   {self.result.medium_count}")
        lines.append(f"   🟢 Low:      {self.result.low_count}")
        lines.append(f"   📊 Total:    {self.result.total_findings}")
        lines.append("")
        
        # Findings by type
        type_counts: Dict[str, int] = {}
        for finding in self.result.findings:
            type_name = finding.secret_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            
        if type_counts:
            lines.append("-" * 80)
            lines.append("📂 Findings by Type")
            lines.append("-" * 80)
            for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                lines.append(f"   {type_name}: {count}")
            lines.append("")
        
        # Detailed findings
        if self.result.findings:
            lines.append("-" * 80)
            lines.append("🔍 Detailed Findings")
            lines.append("-" * 80)
            lines.append("")
            
            for i, finding in enumerate(self.result.findings, 1):
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🟢",
                    Severity.INFO: "⚪",
                }.get(finding.severity, "⚪")
                
                lines.append(f"{severity_emoji} Finding #{i}")
                lines.append(f"   Rule: {finding.rule_name}")
                lines.append(f"   Type: {finding.secret_type.value}")
                lines.append(f"   Severity: {finding.severity.value.upper()}")
                lines.append(f"   Risk Score: {finding.risk_score:.1f}/100")
                lines.append(f"   File: {finding.file_path}:{finding.line_number}")
                lines.append(f"   Content: {finding.line_content[:80]}")
                lines.append(f"   Confidence: {finding.confidence:.0%}")
                lines.append("")
                
        lines.append("=" * 80)
        lines.append("✅ Scan Complete")
        lines.append("=" * 80)
        
        return "\n".join(lines)
        
    def _build_html(self) -> str:
        """Build HTML report content."""
        findings_html = ""
        for i, finding in enumerate(self.result.findings, 1):
            severity_class = finding.severity.value
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-number">#{i}</span>
                    <span class="finding-severity">{finding.severity.value.upper()}</span>
                    <span class="finding-risk">Risk: {finding.risk_score:.1f}/100</span>
                </div>
                <div class="finding-body">
                    <p><strong>Rule:</strong> {finding.rule_name}</p>
                    <p><strong>Type:</strong> {finding.secret_type.value}</p>
                    <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
                    <p><strong>Content:</strong> <code>{finding.line_content[:100]}</code></p>
                    <p><strong>Confidence:</strong> {finding.confidence:.0%}</p>
                    <p><strong>Description:</strong> {finding.description}</p>
                </div>
            </div>
            """
            
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Secret Guard - Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card .number {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card.critical .number {{ color: #dc3545; }}
        .summary-card.high .number {{ color: #fd7e14; }}
        .summary-card.medium .number {{ color: #ffc107; }}
        .summary-card.low .number {{ color: #28a745; }}
        .findings {{ background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 30px; }}
        .finding {{ border-left: 4px solid #ddd; padding: 20px; margin-bottom: 20px; background: #fafafa; border-radius: 5px; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .finding-number {{ font-size: 1.2em; font-weight: bold; color: #666; }}
        .finding-severity {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.85em; }}
        .finding.critical .finding-severity {{ background: #dc3545; }}
        .finding.high .finding-severity {{ background: #fd7e14; }}
        .finding.medium .finding-severity {{ background: #ffc107; color: #333; }}
        .finding.low .finding-severity {{ background: #28a745; }}
        .finding-risk {{ font-weight: bold; color: #666; }}
        .finding-body p {{ margin-bottom: 8px; }}
        code {{ background: #e9ecef; padding: 2px 8px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; }}
        .footer {{ text-align: center; margin-top: 30px; padding: 20px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 AI Secret Guard</h1>
            <p>Scan Report | {self.result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Repository: {self.result.repository_path}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <div class="number">{self.result.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{self.result.high_count}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{self.result.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{self.result.low_count}</div>
                <div>Low</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>🔍 Detailed Findings ({self.result.total_findings})</h2>
            {findings_html if findings_html else '<p>No secrets detected! 🎉</p>'}
        </div>
        
        <div class="footer">
            <p>Generated by AI Secret Guard v1.0.0</p>
        </div>
    </div>
</body>
</html>"""
