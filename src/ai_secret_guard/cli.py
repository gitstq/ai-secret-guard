"""
Command-line interface for AI Secret Guard.
AI Secret Guard的命令行界面。
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

from .scanner import SecretScanner
from .models import ScanConfig
from .reporter import ReportGenerator


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='ai-secret-guard',
        description='🔒 AI Secret Guard - Intelligent Secret Detection & Risk Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ai-secret-guard scan /path/to/repo
  ai-secret-guard scan /path/to/repo --format html --output report.html
  ai-secret-guard scan /path/to/repo --no-ai --workers 8
  ai-secret-guard file /path/to/file.py
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a repository')
    scan_parser.add_argument('path', help='Path to repository')
    scan_parser.add_argument(
        '-f', '--format',
        choices=['console', 'json', 'html'],
        default='console',
        help='Output format (default: console)'
    )
    scan_parser.add_argument(
        '-o', '--output',
        help='Output file path'
    )
    scan_parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI-enhanced detection'
    )
    scan_parser.add_argument(
        '-w', '--workers',
        type=int,
        default=4,
        help='Number of worker threads (default: 4)'
    )
    scan_parser.add_argument(
        '--max-file-size',
        type=int,
        default=10,
        help='Max file size in MB (default: 10)'
    )
    scan_parser.add_argument(
        '--ignore',
        action='append',
        default=[],
        help='Additional ignore patterns'
    )
    
    # File command
    file_parser = subparsers.add_parser('file', help='Scan a single file')
    file_parser.add_argument('path', help='Path to file')
    file_parser.add_argument(
        '-f', '--format',
        choices=['console', 'json'],
        default='console',
        help='Output format'
    )
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    return parser


def print_progress(progress: int, message: str):
    """Print progress bar."""
    bar_length = 40
    filled = int(bar_length * progress / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    sys.stdout.write(f'\r|{bar}| {progress}% {message[:50]}')
    sys.stdout.flush()
    if progress >= 100:
        sys.stdout.write('\n')


def scan_repository(args) -> int:
    """Handle repository scan command."""
    config = ScanConfig(
        ai_enabled=not args.no_ai,
        max_workers=args.workers,
        max_file_size=args.max_file_size * 1024 * 1024,
        custom_ignore_patterns=args.ignore,
    )
    
    scanner = SecretScanner(config)
    
    print(f"🔍 Scanning repository: {args.path}")
    print("-" * 60)
    
    try:
        result = scanner.scan_repository(args.path, progress_callback=print_progress)
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return 1
        
    # Generate report
    reporter = ReportGenerator(result)
    
    if args.format == 'json':
        output = reporter.generate_json_report(args.output)
        if not args.output:
            print(output)
    elif args.format == 'html':
        output = reporter.generate_html_report(args.output)
        if not args.output:
            print(output)
    else:
        print(reporter.generate_console_report())
        
    # Return exit code based on findings
    return 1 if result.critical_count > 0 or result.high_count > 0 else 0


def scan_file(args) -> int:
    """Handle single file scan command."""
    scanner = SecretScanner()
    
    print(f"🔍 Scanning file: {args.path}")
    print("-" * 60)
    
    try:
        findings = scanner.scan_single_file(args.path)
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1
        
    if not findings:
        print("✅ No secrets detected!")
        return 0
        
    print(f"⚠️  Found {len(findings)} potential secret(s):\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"  {i}. [{finding.severity.value.upper()}] {finding.rule_name}")
        print(f"     Line {finding.line_number}: {finding.line_content[:60]}")
        print(f"     Risk Score: {finding.risk_score:.1f}/100")
        print()
        
    return 1 if any(f.severity.value in ['critical', 'high'] for f in findings) else 0


def main(argv: Optional[list] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    setup_logging(args.verbose)
    
    if args.command == 'scan':
        return scan_repository(args)
    elif args.command == 'file':
        return scan_file(args)
    elif args.command == 'version':
        print("AI Secret Guard v1.0.0")
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
