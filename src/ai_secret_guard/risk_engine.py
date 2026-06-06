"""
Risk assessment engine for calculating secret exposure risk.
风险评估引擎，用于计算密钥暴露风险。
"""

from typing import Dict, List
from dataclasses import dataclass
import logging

from .models import Finding, SecretType, Severity, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class RiskFactor:
    """Individual risk factor with weight."""
    name: str
    weight: float
    condition: callable


class RiskEngine:
    """
    Calculates risk scores for detected secrets.
    计算检测到密钥的风险分数。
    """
    
    # Risk weights for different secret types
    TYPE_RISK_WEIGHTS = {
        SecretType.API_KEY: 1.0,
        SecretType.PRIVATE_KEY: 1.0,
        SecretType.DATABASE_URL: 0.9,
        SecretType.PASSWORD: 0.8,
        SecretType.JWT_TOKEN: 0.7,
        SecretType.OAUTH_TOKEN: 0.75,
        SecretType.CREDENTIALS: 0.85,
        SecretType.TOKEN: 0.6,
        SecretType.CERTIFICATE: 0.9,
        SecretType.OTHER: 0.5,
    }
    
    # Severity base scores
    SEVERITY_SCORES = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 75,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 10,
    }
    
    def __init__(self):
        self.risk_factors = self._build_risk_factors()
        
    def _build_risk_factors(self) -> List[RiskFactor]:
        """Build the list of risk factors."""
        factors = []
        
        # Factor: Secret is in a production config file
        factors.append(RiskFactor(
            name="production_config",
            weight=20.0,
            condition=lambda f: any(
                keyword in f.file_path.lower() 
                for keyword in ['prod', 'production', 'live', 'main', 'master']
            )
        ))
        
        # Factor: Secret is in source code (not config)
        factors.append(RiskFactor(
            name="hardcoded_in_source",
            weight=15.0,
            condition=lambda f: any(
                f.file_path.endswith(ext) 
                for ext in ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs']
            )
        ))
        
        # Factor: High confidence match
        factors.append(RiskFactor(
            name="high_confidence",
            weight=10.0,
            condition=lambda f: f.confidence > 0.85
        ))
        
        # Factor: Secret in public-facing file
        factors.append(RiskFactor(
            name="public_file",
            weight=15.0,
            condition=lambda f: any(
                keyword in f.file_path.lower()
                for keyword in ['public', 'assets', 'static', 'dist', 'build']
            )
        ))
        
        # Factor: Long secret (more valuable)
        factors.append(RiskFactor(
            name="long_secret",
            weight=5.0,
            condition=lambda f: len(f.matched_content) > 50
        ))
        
        # Factor: Contains sensitive keywords in line
        factors.append(RiskFactor(
            name="sensitive_context",
            weight=10.0,
            condition=lambda f: any(
                keyword in f.line_content.lower()
                for keyword in ['secret', 'password', 'token', 'key', 'credential', 'auth']
            )
        ))
        
        # Factor: In test file (reduced risk)
        factors.append(RiskFactor(
            name="test_file",
            weight=-15.0,
            condition=lambda f: any(
                keyword in f.file_path.lower()
                for keyword in ['test', 'spec', 'mock', 'fixture', 'example']
            )
        ))
        
        # Factor: In documentation (reduced risk)
        factors.append(RiskFactor(
            name="documentation",
            weight=-10.0,
            condition=lambda f: any(
                keyword in f.file_path.lower()
                for keyword in ['readme', 'doc', 'md', 'markdown', 'changelog']
            )
        ))
        
        return factors
        
    def calculate_risk(self, finding: Finding) -> float:
        """
        Calculate risk score for a finding (0-100).
        计算发现结果的风险分数（0-100）。
        """
        # Base score from severity
        base_score = self.SEVERITY_SCORES.get(finding.severity, 50)
        
        # Apply secret type weight
        type_weight = self.TYPE_RISK_WEIGHTS.get(finding.secret_type, 0.5)
        weighted_score = base_score * type_weight
        
        # Apply risk factors
        factor_adjustment = 0.0
        for factor in self.risk_factors:
            try:
                if factor.condition(finding):
                    factor_adjustment += factor.weight
            except Exception as e:
                logger.debug(f"Risk factor evaluation error: {e}")
                
        # Apply confidence multiplier
        confidence_multiplier = finding.confidence
        
        # Calculate final score
        final_score = (weighted_score + factor_adjustment) * confidence_multiplier
        
        # Clamp to 0-100 range
        return max(0.0, min(100.0, final_score))
        
    def get_risk_level(self, score: float) -> RiskLevel:
        """
        Convert risk score to risk level.
        将风险分数转换为风险等级。
        """
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
            
    def get_remediation_advice(self, finding: Finding) -> str:
        """
        Get remediation advice for a finding.
        获取发现结果的修复建议。
        """
        advice_map = {
            SecretType.API_KEY: (
                "🔑 API密钥修复建议:\n"
                "  1. 立即撤销此API密钥并生成新的密钥\n"
                "  2. 将密钥存储在环境变量或密钥管理服务中\n"
                "  3. 使用.gitignore排除包含密钥的配置文件\n"
                "  4. 考虑使用密钥轮换策略"
            ),
            SecretType.PRIVATE_KEY: (
                "🔐 私钥修复建议:\n"
                "  1. 立即生成新的密钥对\n"
                "  2. 从仓库历史中彻底删除此私钥\n"
                "  3. 使用SSH代理或密钥管理系统存储私钥\n"
                "  4. 更新所有使用此密钥的服务"
            ),
            SecretType.DATABASE_URL: (
                "🗄️ 数据库连接字符串修复建议:\n"
                "  1. 更改数据库密码\n"
                "  2. 使用连接池或数据库代理服务\n"
                "  3. 将连接字符串存储在环境变量中\n"
                "  4. 限制数据库访问IP范围"
            ),
            SecretType.PASSWORD: (
                "🔒 密码修复建议:\n"
                "  1. 立即更改此密码\n"
                "  2. 使用密码管理器或密钥管理服务\n"
                "  3. 实施密码策略（最小长度、复杂度要求）\n"
                "  4. 考虑使用单点登录（SSO）"
            ),
            SecretType.JWT_TOKEN: (
                "🎫 JWT令牌修复建议:\n"
                "  1. 撤销此令牌并重新签发\n"
                "  2. 缩短令牌有效期\n"
                "  3. 实施令牌刷新机制\n"
                "  4. 使用安全的令牌存储方式"
            ),
            SecretType.OAUTH_TOKEN: (
                "🔓 OAuth令牌修复建议:\n"
                "  1. 撤销此OAuth令牌\n"
                "  2. 重新授权应用\n"
                "  3. 限制令牌权限范围\n"
                "  4. 监控令牌使用情况"
            ),
        }
        
        return advice_map.get(
            finding.secret_type,
            "⚠️ 通用修复建议:\n"
            "  1. 从代码仓库中删除此敏感信息\n"
            "  2. 使用环境变量或密钥管理服务\n"
            "  3. 审查仓库历史确保彻底删除\n"
            "  4. 轮换相关凭证"
        )
