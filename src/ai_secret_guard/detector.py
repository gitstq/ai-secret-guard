"""
Detection modules for identifying secrets in code.
密钥检测模块，用于识别代码中的敏感信息。
"""

import re
import hashlib
from typing import List, Dict, Pattern, Optional, Tuple
from dataclasses import dataclass
import logging

from .models import Finding, SecretType, Severity

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Rule for detecting a specific type of secret."""
    name: str
    secret_type: SecretType
    pattern: Pattern
    severity: Severity
    description: str
    example: str
    false_positive_indicators: List[str]


class PatternDetector:
    """
    Pattern-based secret detector using regex rules.
    基于正则规则的密钥检测器。
    """
    
    def __init__(self):
        self.rules = self._build_rules()
        
    def _build_rules(self) -> List[DetectionRule]:
        """Build the comprehensive rule set for secret detection."""
        rules = []
        
        # API Keys
        rules.append(DetectionRule(
            name="OpenAI API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE),
            severity=Severity.CRITICAL,
            description="OpenAI API密钥，可用于访问GPT模型",
            example="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake", "dummy", "placeholder"]
        ))
        
        rules.append(DetectionRule(
            name="AWS Access Key ID",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
            severity=Severity.CRITICAL,
            description="AWS访问密钥ID",
            example="AKIAIOSFODNN7EXAMPLE",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        rules.append(DetectionRule(
            name="AWS Secret Access Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'[0-9a-zA-Z/+]{40}', re.IGNORECASE),
            severity=Severity.CRITICAL,
            description="AWS秘密访问密钥",
            example="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        rules.append(DetectionRule(
            name="GitHub Personal Access Token",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'ghp_[a-zA-Z0-9]{36}'),
            severity=Severity.CRITICAL,
            description="GitHub个人访问令牌",
            example="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        rules.append(DetectionRule(
            name="GitHub OAuth Token",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'gho_[a-zA-Z0-9]{36}', re.IGNORECASE),
            severity=Severity.CRITICAL,
            description="GitHub OAuth令牌",
            example="gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        rules.append(DetectionRule(
            name="Slack API Token",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}', re.IGNORECASE),
            severity=Severity.HIGH,
            description="Slack API令牌",
            example="xoxb-REDACTED-EXAMPLE-TOKEN-FOR-DOCS",
            false_positive_indicators=["example", "test", "fake", "REDACTED"]
        ))
        
        rules.append(DetectionRule(
            name="Stripe API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,}', re.IGNORECASE),
            severity=Severity.CRITICAL,
            description="Stripe API密钥（支付平台）",
            example="sk_live_REDACTED_EXAMPLE_KEY_FOR_DOCUMENTATION",
            false_positive_indicators=["example", "test", "fake", "REDACTED"]
        ))
        
        rules.append(DetectionRule(
            name="Generic API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(
                r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
                re.IGNORECASE
            ),
            severity=Severity.MEDIUM,
            description="通用API密钥格式",
            example="api_key: xxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake", "your_key", "insert"]
        ))
        
        # Database Credentials
        rules.append(DetectionRule(
            name="Database Connection String",
            secret_type=SecretType.DATABASE_URL,
            pattern=re.compile(
                r'(mongodb|mysql|postgresql|postgres|redis)://[^\s"\']+'
            ),
            severity=Severity.CRITICAL,
            description="数据库连接字符串（包含密码）",
            example="mongodb://user:password@host:port/db",
            false_positive_indicators=["example", "test", "fake", "localhost"]
        ))
        
        rules.append(DetectionRule(
            name="Database Password",
            secret_type=SecretType.PASSWORD,
            pattern=re.compile(
                r'(?i)(db[_-]?pass|database[_-]?pass|db[_-]?password)\s*[:=]\s*["\']?[^\s"\']+["\']?',
                re.IGNORECASE
            ),
            severity=Severity.HIGH,
            description="数据库密码",
            example="db_password: secret123",
            false_positive_indicators=["example", "test", "fake", "password"]
        ))
        
        # Private Keys
        rules.append(DetectionRule(
            name="RSA Private Key",
            secret_type=SecretType.PRIVATE_KEY,
            pattern=re.compile(
                r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                re.IGNORECASE
            ),
            severity=Severity.CRITICAL,
            description="RSA/EC/DSA私钥",
            example="-----BEGIN RSA PRIVATE KEY-----\n...",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        rules.append(DetectionRule(
            name="SSH Private Key",
            secret_type=SecretType.PRIVATE_KEY,
            pattern=re.compile(
                r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----',
                re.IGNORECASE
            ),
            severity=Severity.CRITICAL,
            description="SSH私钥",
            example="-----BEGIN OPENSSH PRIVATE KEY-----\n...",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # JWT Tokens
        rules.append(DetectionRule(
            name="JWT Token",
            secret_type=SecretType.JWT_TOKEN,
            pattern=re.compile(
                r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                re.IGNORECASE
            ),
            severity=Severity.HIGH,
            description="JSON Web Token",
            example="eyJhbGciOiJIUzI1NiIs...",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # OAuth Tokens
        rules.append(DetectionRule(
            name="OAuth 2.0 Bearer Token",
            secret_type=SecretType.OAUTH_TOKEN,
            pattern=re.compile(
                r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+',
                re.IGNORECASE
            ),
            severity=Severity.HIGH,
            description="OAuth 2.0 Bearer令牌",
            example="Bearer eyJhbGciOiJIUzI1NiIs...",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # Passwords
        rules.append(DetectionRule(
            name="Hardcoded Password",
            secret_type=SecretType.PASSWORD,
            pattern=re.compile(
                r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^\s"\']{8,}["\']',
                re.IGNORECASE
            ),
            severity=Severity.HIGH,
            description="硬编码密码",
            example="password: 'mysecretpassword'",
            false_positive_indicators=["example", "test", "fake", "password", "changeme"]
        ))
        
        # Google API Keys
        rules.append(DetectionRule(
            name="Google API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'AIza[0-9A-Za-z_-]{35}', re.IGNORECASE),
            severity=Severity.HIGH,
            description="Google API密钥",
            example="AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # Twilio
        rules.append(DetectionRule(
            name="Twilio API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'SK[0-9a-fA-F]{32}', re.IGNORECASE),
            severity=Severity.HIGH,
            description="Twilio API密钥",
            example="SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # SendGrid
        rules.append(DetectionRule(
            name="SendGrid API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', re.IGNORECASE),
            severity=Severity.HIGH,
            description="SendGrid API密钥",
            example="SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        # Heroku
        rules.append(DetectionRule(
            name="Heroku API Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                re.IGNORECASE
            ),
            severity=Severity.MEDIUM,
            description="Heroku API密钥（UUID格式）",
            example="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            false_positive_indicators=["example", "test", "fake", "uuid"]
        ))
        
        # Azure
        rules.append(DetectionRule(
            name="Azure Storage Account Key",
            secret_type=SecretType.API_KEY,
            pattern=re.compile(
                r'[0-9a-zA-Z+/]{86}==',
                re.IGNORECASE
            ),
            severity=Severity.CRITICAL,
            description="Azure存储账户密钥",
            example="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==",
            false_positive_indicators=["example", "test", "fake"]
        ))
        
        return rules
        
    def detect(self, content: str, file_path: str) -> List[Finding]:
        """
        Detect secrets in content using all rules.
        使用所有规则检测内容中的密钥。
        """
        findings = []
        lines = content.split('\n')
        
        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Extract the matched secret
                secret_value = match.group(0)
                
                # Skip if looks like a false positive
                if self._is_false_positive(secret_value, line_content, rule.false_positive_indicators):
                    continue
                    
                # Calculate position in line
                col_start = match.start() - content.rfind('\n', 0, match.start()) - 1
                if col_start < 0:
                    col_start = match.start()
                    
                finding = Finding(
                    rule_name=rule.name,
                    secret_type=rule.secret_type,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=line_num,
                    column_start=col_start,
                    column_end=col_start + len(secret_value),
                    matched_content=secret_value,
                    line_content=line_content.strip(),
                    description=rule.description,
                    confidence=self._calculate_confidence(secret_value, line_content, rule),
                    risk_score=0.0,  # Will be calculated by risk engine
                    risk_level="unknown"
                )
                findings.append(finding)
                
        return findings
        
    def _is_false_positive(
        self, 
        secret_value: str, 
        line_content: str,
        indicators: List[str]
    ) -> bool:
        """
        Check if a match is likely a false positive.
        检查匹配是否可能是误报。
        """
        line_lower = line_content.lower()
        secret_lower = secret_value.lower()
        
        # Check for common false positive indicators in the line
        for indicator in indicators:
            if indicator.lower() in line_lower:
                return True
                
        # Check for placeholder patterns
        placeholder_patterns = [
            r'your_\w+_here',
            r'xxx+',
            r'\*\*\*+',
            r'<\w+>',
            r'\{\{\s*\w+\s*\}\}',
            r'\$\{\w+\}',
            r'process\.env\.',
            r'os\.environ',
            r'getenv',
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, line_lower):
                return True
                
        return False
        
    def _calculate_confidence(
        self, 
        secret_value: str,
        line_content: str,
        rule: DetectionRule
    ) -> float:
        """
        Calculate confidence score for a match.
        计算匹配的置信度分数。
        """
        confidence = 0.7  # Base confidence
        
        # Higher confidence for longer secrets
        if len(secret_value) > 32:
            confidence += 0.1
            
        # Higher confidence if line contains assignment
        if re.search(r'[=:]', line_content):
            confidence += 0.1
            
        # Lower confidence if in comments
        if re.search(r'^(\s*#|\s*//|\s*\*|\s*<!--)', line_content):
            confidence -= 0.2
            
        # Higher confidence for well-known prefixes
        well_known_prefixes = ['sk-', 'AKIA', 'ghp_', 'gho_', 'xoxb-', 'eyJ']
        if any(secret_value.startswith(prefix) for prefix in well_known_prefixes):
            confidence += 0.15
            
        return min(max(confidence, 0.0), 1.0)


class AIEnhancedDetector:
    """
    AI-enhanced detector for reducing false positives.
    AI增强检测器，用于降低误报率。
    
    This is a lightweight implementation that uses heuristics
    and contextual analysis to improve detection quality.
    """
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        
    def enhance_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Apply AI-enhanced analysis to findings.
        对发现结果应用AI增强分析。
        """
        if not self.enabled:
            return findings
            
        enhanced = []
        for finding in findings:
            # Apply contextual analysis
            finding = self._analyze_context(finding)
            
            # Filter out obvious false positives
            if not self._is_obvious_false_positive(finding):
                enhanced.append(finding)
                
        return enhanced
        
    def _analyze_context(self, finding: Finding) -> Finding:
        """
        Analyze the context around a finding to improve accuracy.
        分析发现结果周围的上下文以提高准确性。
        """
        line = finding.line_content.lower()
        
        # Check for environment variable patterns (likely safe)
        if re.search(r'(env|environment|config|settings)', line):
            finding.confidence -= 0.1
            
        # Check for test files
        if re.search(r'(test|spec|mock|fixture)', finding.file_path.lower()):
            finding.confidence -= 0.15
            finding.severity = self._lower_severity(finding.severity)
            
        # Check for documentation
        if re.search(r'(readme|doc|example|sample)', finding.file_path.lower()):
            finding.confidence -= 0.2
            finding.severity = self._lower_severity(finding.severity)
            
        # Check for encrypted/hashed values
        if re.search(r'(bcrypt|scrypt|argon|sha256|md5|hash)', line):
            finding.confidence -= 0.3
            
        # Ensure confidence stays in valid range
        finding.confidence = max(0.0, min(1.0, finding.confidence))
        
        return finding
        
    def _is_obvious_false_positive(self, finding: Finding) -> bool:
        """
        Check if a finding is an obvious false positive.
        检查发现结果是否是明显的误报。
        """
        # Very low confidence findings
        if finding.confidence < 0.3:
            return True
            
        # Check for example/placeholder values
        secret = finding.matched_content.lower()
        if re.search(r'(example|test|fake|dummy|placeholder|your_|xxx+|changeme)', secret):
            return True
            
        return False
        
    def _lower_severity(self, severity: Severity) -> Severity:
        """Lower the severity level by one step."""
        severity_map = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO
        }
        return severity_map.get(severity, severity)
