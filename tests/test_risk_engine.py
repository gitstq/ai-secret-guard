"""
Tests for the risk engine module.
风险评估引擎模块的测试。
"""

import pytest
from ai_secret_guard.risk_engine import RiskEngine
from ai_secret_guard.models import Finding, SecretType, Severity, RiskLevel


class TestRiskEngine:
    """Test cases for RiskEngine."""
    
    def test_calculate_risk_api_key(self):
        """Test risk calculation for API key."""
        engine = RiskEngine()
        
        finding = Finding(
            rule_name="OpenAI API Key",
            secret_type=SecretType.API_KEY,
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-xxx",
            line_content="api_key = 'sk-xxx'",
            description="Test",
            confidence=0.9,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        score = engine.calculate_risk(finding)
        assert 0.0 <= score <= 100.0
        assert score > 50.0  # API key should have high risk
        
    def test_calculate_risk_private_key(self):
        """Test risk calculation for private key."""
        engine = RiskEngine()
        
        finding = Finding(
            rule_name="RSA Private Key",
            secret_type=SecretType.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            file_path="keys/id_rsa",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="-----BEGIN",
            line_content="-----BEGIN RSA PRIVATE KEY-----",
            description="Test",
            confidence=0.95,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        score = engine.calculate_risk(finding)
        assert score > 60.0  # Private key should have very high risk
        
    def test_risk_level_critical(self):
        """Test risk level classification for critical."""
        engine = RiskEngine()
        assert engine.get_risk_level(85.0) == RiskLevel.CRITICAL
        assert engine.get_risk_level(100.0) == RiskLevel.CRITICAL
        
    def test_risk_level_high(self):
        """Test risk level classification for high."""
        engine = RiskEngine()
        assert engine.get_risk_level(70.0) == RiskLevel.HIGH
        assert engine.get_risk_level(60.0) == RiskLevel.HIGH
        
    def test_risk_level_medium(self):
        """Test risk level classification for medium."""
        engine = RiskEngine()
        assert engine.get_risk_level(50.0) == RiskLevel.MEDIUM
        assert engine.get_risk_level(40.0) == RiskLevel.MEDIUM
        
    def test_risk_level_low(self):
        """Test risk level classification for low."""
        engine = RiskEngine()
        assert engine.get_risk_level(30.0) == RiskLevel.LOW
        assert engine.get_risk_level(20.0) == RiskLevel.LOW
        
    def test_risk_level_info(self):
        """Test risk level classification for info."""
        engine = RiskEngine()
        assert engine.get_risk_level(10.0) == RiskLevel.INFO
        assert engine.get_risk_level(0.0) == RiskLevel.INFO
        
    def test_production_config_risk(self):
        """Test that production config files get higher risk."""
        engine = RiskEngine()
        
        finding_prod = Finding(
            rule_name="API Key",
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            file_path="config/production.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-xxx",
            line_content="api_key = 'sk-xxx'",
            description="Test",
            confidence=0.8,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        finding_test = Finding(
            rule_name="API Key",
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            file_path="tests/test_api.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-xxx",
            line_content="api_key = 'sk-xxx'",
            description="Test",
            confidence=0.8,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        prod_score = engine.calculate_risk(finding_prod)
        test_score = engine.calculate_risk(finding_test)
        
        assert prod_score > test_score  # Production should be higher risk
        
    def test_remediation_advice(self):
        """Test remediation advice generation."""
        engine = RiskEngine()
        
        finding = Finding(
            rule_name="OpenAI API Key",
            secret_type=SecretType.API_KEY,
            severity=Severity.CRITICAL,
            file_path="test.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-xxx",
            line_content="api_key = 'sk-xxx'",
            description="Test",
            confidence=0.9,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        advice = engine.get_remediation_advice(finding)
        assert "API" in advice or "密钥" in advice
        assert len(advice) > 0
