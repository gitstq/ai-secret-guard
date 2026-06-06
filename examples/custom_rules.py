"""
Custom rules example for AI Secret Guard.
AI Secret Guard自定义规则示例。
"""

import re
from ai_secret_guard.detector import PatternDetector, DetectionRule
from ai_secret_guard.models import SecretType, Severity

# Create detector with custom rules
detector = PatternDetector()

# Add custom rule for your company's internal API key
custom_rule = DetectionRule(
    name="MyCompany Internal API Key",
    secret_type=SecretType.API_KEY,
    pattern=re.compile(r'mycompany_[a-zA-Z0-9]{32}'),
    severity=Severity.HIGH,
    description="公司内部API密钥",
    example="mycompany_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    false_positive_indicators=["example", "test", "fake"]
)

# Add to detector's rules
detector.rules.append(custom_rule)

# Now scan with custom rules
content = "api_key = 'mycompany_abcdefghijklmnopqrstuvwxyz12'"
findings = detector.detect(content, "config.py")

for finding in findings:
    print(f"Found: {finding.rule_name} at line {finding.line_number}")
