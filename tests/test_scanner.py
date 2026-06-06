"""
Tests for the scanner module.
扫描器模块的测试。
"""

import pytest
import tempfile
from pathlib import Path

from ai_secret_guard.scanner import SecretScanner
from ai_secret_guard.models import ScanConfig


class TestSecretScanner:
    """Test cases for SecretScanner."""
    
    def test_scan_empty_repository(self):
        """Test scanning an empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = SecretScanner()
            result = scanner.scan_repository(tmpdir)
            
            assert result.total_findings == 0
            assert result.files_scanned == 0
            
    def test_scan_with_secrets(self):
        """Test scanning a repository with secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with a secret
            secret_file = Path(tmpdir) / "config.py"
            secret_file.write_text("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'\n")
            
            scanner = SecretScanner()
            result = scanner.scan_repository(tmpdir)
            
            assert result.total_findings >= 1
            assert result.files_scanned >= 1
            
    def test_scan_single_file(self):
        """Test scanning a single file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'\n")
            f.flush()
            
            scanner = SecretScanner()
            findings = scanner.scan_single_file(f.name)
            
            assert len(findings) >= 1
            
            Path(f.name).unlink()
            
    def test_scan_ignores_binary_files(self):
        """Test that binary files are ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a binary file
            binary_file = Path(tmpdir) / "data.bin"
            binary_file.write_bytes(b'\x00\x01\x02\x03' * 100)
            
            scanner = SecretScanner()
            result = scanner.scan_repository(tmpdir)
            
            assert result.files_scanned == 0
            
    def test_scan_respects_ignore_patterns(self):
        """Test that ignore patterns are respected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files in ignored directories
            node_modules = Path(tmpdir) / "node_modules" / "package"
            node_modules.mkdir(parents=True)
            secret_file = node_modules / "config.js"
            secret_file.write_text("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'\n")
            
            scanner = SecretScanner()
            result = scanner.scan_repository(tmpdir)
            
            # Should not scan node_modules
            assert result.files_scanned == 0
            
    def test_scan_with_custom_config(self):
        """Test scanning with custom configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = Path(tmpdir) / "config.py"
            secret_file.write_text("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'\n")
            
            config = ScanConfig(
                ai_enabled=False,
                max_workers=2,
            )
            scanner = SecretScanner(config)
            result = scanner.scan_repository(tmpdir)
            
            assert result.total_findings >= 1
            
    def test_scan_result_sorting(self):
        """Test that findings are sorted by risk score."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files with different secrets
            file1 = Path(tmpdir) / "production.py"
            file1.write_text("api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMN'\n")
            
            file2 = Path(tmpdir) / "test.py"
            file2.write_text("password = 'test123'\n")
            
            scanner = SecretScanner()
            result = scanner.scan_repository(tmpdir)
            
            if len(result.findings) >= 2:
                # Should be sorted by risk score descending
                scores = [f.risk_score for f in result.findings]
                assert scores == sorted(scores, reverse=True)
