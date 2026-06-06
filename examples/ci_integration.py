"""
CI/CD integration example for AI Secret Guard.
AI Secret Guard CI/CD集成示例。
"""

import sys
from ai_secret_guard import SecretScanner

def ci_scan():
    """
    Scan repository in CI/CD pipeline.
    Returns exit code 1 if critical/high secrets found.
    """
    scanner = SecretScanner()
    result = scanner.scan_repository(".")
    
    print(f"🔍 Scanned {result.files_scanned} files")
    print(f"🔴 Critical: {result.critical_count}")
    print(f"🟠 High: {result.high_count}")
    print(f"🟡 Medium: {result.medium_count}")
    print(f"🟢 Low: {result.low_count}")
    
    # Fail CI if critical or high secrets found
    if result.critical_count > 0 or result.high_count > 0:
        print("❌ CI failed: Critical or high-risk secrets detected!")
        return 1
        
    print("✅ CI passed: No critical secrets detected")
    return 0

if __name__ == "__main__":
    sys.exit(ci_scan())
