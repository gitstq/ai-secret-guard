"""
Tests for the detector module.
检测器模块的测试。
"""

import pytest
from ai_secret_guard.detector import PatternDetector, AIEnhancedDetector
from ai_secret_guard.models import SecretType, Severity


class TestPatternDetector:
    """Test cases for PatternDetector."""
    
    def test_openai_api_key_detection(self):
        """Test detection of OpenAI API keys."""
        detector = PatternDetector()
        content = "api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'"
        findings = detector.detect(content, "test.py")
        
        assert len(findings) >= 1
        assert any(f.rule_name == "OpenAI API Key" for f in findings)
        
    def test_aws_access_key_detection(self):
        """Test detection of AWS access keys."""
        detector = PatternDetector()
        content = "aws_access_key = 'AKIAIOSFODNN7ABCDEFGH'"
        findings = detector.detect(content, "config.py")
        
        assert len(findings) >= 1
        assert any(f.rule_name == "AWS Access Key ID" for f in findings)
        
    def test_github_token_detection(self):
        """Test detection of GitHub tokens."""
        detector = PatternDetector()
        content = "token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD'"
        findings = detector.detect(content, "test.py")
        
        assert len(findings) >= 1
        assert any(f.rule_name == "GitHub Personal Access Token" for f in findings)
        
    def test_private_key_detection(self):
        """Test detection of private keys."""
        detector = PatternDetector()
        content = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwMbRvI0MBZhpJ
-----END RSA PRIVATE KEY-----"""
        findings = detector.detect(content, "key.pem")
        
        assert len(findings) >= 1
        assert any(f.secret_type == SecretType.PRIVATE_KEY for f in findings)
        
    def test_jwt_token_detection(self):
        """Test detection of JWT tokens."""
        detector = PatternDetector()
        content = "auth_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
        findings = detector.detect(content, "test.py")
        
        assert len(findings) >= 1
        assert any(f.rule_name == "JWT Token" for f in findings)
        
    def test_false_positive_filtering(self):
        """Test that false positives are filtered out."""
        detector = PatternDetector()
        content = "api_key = 'your_api_key_here'  # example"
        findings = detector.detect(content, "test.py")
        
        # Should filter out obvious placeholders
        assert not any(f.rule_name == "Generic API Key" for f in findings)
        
    def test_database_url_detection(self):
        """Test detection of database connection strings."""
        detector = PatternDetector()
        content = "DATABASE_URL = 'mongodb://admin:password123@dbserver:27017/mydb'"
        findings = detector.detect(content, "config.py")
        
        assert len(findings) >= 1
        assert any(f.secret_type == SecretType.DATABASE_URL for f in findings)
        
    def test_confidence_calculation(self):
        """Test confidence score calculation."""
        detector = PatternDetector()
        content = "sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN"
        findings = detector.detect(content, "test.py")
        
        if findings:
            assert 0.0 <= findings[0].confidence <= 1.0
            assert findings[0].confidence > 0.5  # Should have reasonable confidence


class TestAIEnhancedDetector:
    """Test cases for AIEnhancedDetector."""
    
    def test_enhance_findings(self):
        """Test AI enhancement of findings."""
        from ai_secret_guard.models import Finding
        
        detector = AIEnhancedDetector(enabled=True)
        
        finding = Finding(
            rule_name="Test",
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-test",
            line_content="api_key = 'sk-test'",
            description="Test",
            confidence=0.8,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        enhanced = detector.enhance_findings([finding])
        assert len(enhanced) <= 1  # May filter out some
        
    def test_disabled_detector(self):
        """Test that disabled detector passes findings through."""
        from ai_secret_guard.models import Finding
        
        detector = AIEnhancedDetector(enabled=False)
        
        finding = Finding(
            rule_name="Test",
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            column_start=0,
            column_end=10,
            matched_content="sk-test",
            line_content="api_key = 'sk-test'",
            description="Test",
            confidence=0.8,
            risk_score=0.0,
            risk_level="unknown"
        )
        
        enhanced = detector.enhance_findings([finding])
        assert len(enhanced) == 1
        assert enhanced[0] == finding
