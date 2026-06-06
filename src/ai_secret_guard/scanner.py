"""
Core scanner module for repository scanning and orchestration.
核心扫描模块，负责仓库扫描与任务编排。
"""

import os
import re
import hashlib
import fnmatch
from pathlib import Path
from typing import List, Dict, Iterator, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .detector import PatternDetector, AIEnhancedDetector
from .risk_engine import RiskEngine
from .models import Finding, ScanResult, ScanConfig

logger = logging.getLogger(__name__)


class SecretScanner:
    """
    Main scanner class that orchestrates the secret detection process.
    主扫描器类，负责编排密钥检测流程。
    """
    
    DEFAULT_IGNORE_PATTERNS = [
        "*.min.js", "*.min.css", "*.map",
        "node_modules/*", "vendor/*", ".git/*",
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
        "*.woff", "*.woff2", "*.ttf", "*.eot",
        "*.mp3", "*.mp4", "*.avi", "*.mov",
        "*.zip", "*.tar.gz", "*.rar", "*.7z",
        "*.exe", "*.dll", "*.so", "*.dylib",
        "*.pyc", "__pycache__/*", "*.class",
        ".env", ".env.local", ".env.*.local",
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "*.log", "*.tmp", "*.temp", "*.swp", "*.swo",
        ".idea/*", ".vscode/*", ".DS_Store",
        "dist/*", "build/*", "target/*", "out/*",
    ]
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Scan configuration. If None, uses default config.
        """
        self.config = config or ScanConfig()
        self.pattern_detector = PatternDetector()
        self.ai_detector = AIEnhancedDetector(enabled=self.config.ai_enabled)
        self.risk_engine = RiskEngine()
        self._file_cache: Dict[str, str] = {}
        self._scanned_hashes: Set[str] = set()
        
    def scan_repository(
        self, 
        repo_path: str,
        progress_callback=None
    ) -> ScanResult:
        """
        Scan a repository for secrets.
        扫描仓库中的密钥泄露。
        
        Args:
            repo_path: Path to the repository root
            progress_callback: Optional callback function(progress_pct, message)
            
        Returns:
            ScanResult containing all findings
        """
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")
            
        logger.info(f"🔍 Starting scan of repository: {repo_path}")
        
        findings: List[Finding] = []
        files_scanned = 0
        files_skipped = 0
        
        # Collect all scannable files
        files_to_scan = list(self._collect_files(repo_path))
        total_files = len(files_to_scan)
        
        logger.info(f"📁 Found {total_files} files to scan")
        
        # Scan files with thread pool for performance
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_file = {
                executor.submit(self._scan_file, file_path, repo_path): file_path 
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_findings = future.result()
                    findings.extend(file_findings)
                    files_scanned += 1
                    
                    if progress_callback:
                        progress = int((files_scanned / total_files) * 100)
                        progress_callback(progress, f"Scanned: {file_path.name}")
                        
                except Exception as e:
                    logger.warning(f"⚠️ Error scanning {file_path}: {e}")
                    files_skipped += 1
                    
        # Apply AI enhancement if enabled
        if self.config.ai_enabled:
            logger.info("🤖 Applying AI-enhanced analysis...")
            findings = self.ai_detector.enhance_findings(findings)
            
        # Calculate risk scores
        logger.info("🎯 Calculating risk scores...")
        for finding in findings:
            finding.risk_score = self.risk_engine.calculate_risk(finding)
            finding.risk_level = self.risk_engine.get_risk_level(finding.risk_score)
            
        # Sort by risk score (highest first)
        findings.sort(key=lambda f: f.risk_score, reverse=True)
        
        result = ScanResult(
            findings=findings,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            repository_path=str(repo_path),
            scan_config=self.config
        )
        
        logger.info(f"✅ Scan complete! Found {len(findings)} potential secrets")
        return result
        
    def _collect_files(self, repo_path: Path) -> Iterator[Path]:
        """
        Collect all files that should be scanned.
        收集所有需要扫描的文件。
        """
        ignore_patterns = self.DEFAULT_IGNORE_PATTERNS + self.config.custom_ignore_patterns
        
        for root, dirs, files in os.walk(repo_path):
            root_path = Path(root)
            
            # Skip ignored directories
            dirs[:] = [
                d for d in dirs 
                if not any(fnmatch.fnmatch(d, pattern.rstrip('/*')) for pattern in ignore_patterns)
            ]
            
            for filename in files:
                file_path = root_path / filename
                
                # Skip ignored file patterns
                relative_path = str(file_path.relative_to(repo_path))
                if any(fnmatch.fnmatch(relative_path, pattern) or 
                       fnmatch.fnmatch(filename, pattern) for pattern in ignore_patterns):
                    continue
                    
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                    
                # Skip files that are too large
                if file_path.stat().st_size > self.config.max_file_size:
                    continue
                    
                yield file_path
                
    def _scan_file(self, file_path: Path, repo_path: Path) -> List[Finding]:
        """
        Scan a single file for secrets.
        扫描单个文件中的密钥。
        """
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")
            return findings
            
        relative_path = str(file_path.relative_to(repo_path))
        
        # Check for pattern-based matches
        pattern_findings = self.pattern_detector.detect(content, relative_path)
        findings.extend(pattern_findings)
        
        return findings
        
    def _is_binary(self, file_path: Path) -> bool:
        """
        Check if a file is binary.
        检查文件是否为二进制文件。
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                return b'\x00' in chunk
        except:
            return True
            
    def scan_single_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single file outside of repository context.
        扫描单个文件（非仓库上下文）。
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        if self._is_binary(file_path):
            return []
            
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []
            
        findings = self.pattern_detector.detect(content, str(file_path.name))
        
        # Apply risk scoring
        for finding in findings:
            finding.risk_score = self.risk_engine.calculate_risk(finding)
            finding.risk_level = self.risk_engine.get_risk_level(finding.risk_score)
            
        return findings
