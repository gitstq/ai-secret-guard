"""
AI Secret Guard - Intelligent Secret Detection & Risk Assessment
AI智能密钥泄露扫描与风险评估工具

A powerful, AI-enhanced secret scanning tool that detects API keys,
passwords, tokens, and other sensitive information in code repositories
with intelligent risk assessment and minimal false positives.
"""

__version__ = "1.0.0"
__author__ = "AI Secret Guard Team"
__license__ = "MIT"

from .scanner import SecretScanner
from .detector import PatternDetector, AIEnhancedDetector
from .risk_engine import RiskEngine
from .reporter import ReportGenerator

__all__ = [
    "SecretScanner",
    "PatternDetector", 
    "AIEnhancedDetector",
    "RiskEngine",
    "ReportGenerator",
]
