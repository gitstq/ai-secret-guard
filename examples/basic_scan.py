"""
Basic usage example for AI Secret Guard.
AI Secret Guard基础使用示例。
"""

from ai_secret_guard import SecretScanner
from ai_secret_guard.reporter import ReportGenerator

# Initialize scanner
scanner = SecretScanner()

# Scan a repository
result = scanner.scan_repository("/path/to/your/repo")

# Generate console report
reporter = ReportGenerator(result)
print(reporter.generate_console_report())

# Generate HTML report
reporter.generate_html_report("scan-report.html")
print("📄 HTML report saved to scan-report.html")
