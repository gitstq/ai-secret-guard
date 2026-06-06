"""
Data models for AI Secret Guard.
AI Secret Guard的数据模型。
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


class SecretType(Enum):
    """Types of secrets that can be detected."""
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    DATABASE_URL = "database_url"
    JWT_TOKEN = "jwt_token"
    OAUTH_TOKEN = "oauth_token"
    CREDENTIALS = "credentials"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    OTHER = "other"


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(Enum):
    """Risk levels based on calculated scores."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single secret finding."""
    rule_name: str
    secret_type: SecretType
    severity: Severity
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    matched_content: str
    line_content: str
    description: str
    confidence: float
    risk_score: float = 0.0
    risk_level: str = "unknown"
    remediation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "rule_name": self.rule_name,
            "secret_type": self.secret_type.value,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "matched_content": self._mask_secret(self.matched_content),
            "line_content": self.line_content,
            "description": self.description,
            "confidence": round(self.confidence, 2),
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "remediation": self.remediation,
        }
        
    def _mask_secret(self, secret: str) -> str:
        """Mask the secret value for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


@dataclass
class ScanConfig:
    """Configuration for scanning."""
    ai_enabled: bool = True
    max_workers: int = 4
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    custom_ignore_patterns: List[str] = field(default_factory=list)
    min_confidence: float = 0.3
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ai_enabled": self.ai_enabled,
            "max_workers": self.max_workers,
            "max_file_size": self.max_file_size,
            "custom_ignore_patterns": self.custom_ignore_patterns,
            "min_confidence": self.min_confidence,
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""
    findings: List[Finding]
    files_scanned: int
    files_skipped: int
    repository_path: str
    scan_config: ScanConfig
    scan_time: datetime = field(default_factory=datetime.now)
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
        
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
        
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
        
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
        
    def get_findings_by_type(self, secret_type: SecretType) -> List[Finding]:
        return [f for f in self.findings if f.secret_type == secret_type]
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_summary": {
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "repository_path": self.repository_path,
                "scan_time": self.scan_time.isoformat(),
            },
            "scan_config": self.scan_config.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
