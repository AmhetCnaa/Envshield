from __future__ import annotations

import re
from dataclasses import dataclass

from envshield.core.base import BaseScanner
from envshield.core.models import Finding, Severity
from envshield.utils.masking import mask_secret


@dataclass
class RegexRule:
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity

# 30+ Regex Rules for secret detection
REGEX_RULES = [
    RegexRule("AWS_ACCESS_KEY", "AWS Access Key ID", re.compile(r"(?i)\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    RegexRule("AWS_SECRET_KEY", "AWS Secret Access Key", re.compile(r"(?i)\b(?:aws_secret|aws_secret_access_key|secret_key)[\s=:]+['\"]?[A-Za-z0-9/+=]{40}['\"]?\b"), Severity.CRITICAL),
    RegexRule("GITHUB_PAT", "GitHub Personal Access Token", re.compile(r"(?i)\bghp_[0-9a-zA-Z]{36}\b"), Severity.CRITICAL),
    RegexRule("GITHUB_OAUTH", "GitHub OAuth Access Token", re.compile(r"(?i)\bgho_[0-9a-zA-Z]{36}\b"), Severity.CRITICAL),
    RegexRule("GITHUB_SERVER_TO_SERVER", "GitHub Server-to-Server Token", re.compile(r"(?i)\bghs_[0-9a-zA-Z]{36}\b"), Severity.CRITICAL),
    RegexRule("GITHUB_REFRESH", "GitHub Refresh Token", re.compile(r"(?i)\bghr_[0-9a-zA-Z]{36}\b"), Severity.CRITICAL),
    RegexRule("STRIPE_TEST_SECRET", "Stripe Test Secret Key", re.compile(r"(?i)\bsk_test_[0-9a-zA-Z]{24}\b"), Severity.HIGH),
    RegexRule("STRIPE_LIVE_SECRET", "Stripe Live Secret Key", re.compile(r"(?i)\bsk_live_[0-9a-zA-Z]{24}\b"), Severity.CRITICAL),
    RegexRule("SLACK_BOT_TOKEN", "Slack Bot Token", re.compile(r"(?i)\bxoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}\b"), Severity.CRITICAL),
    RegexRule("SLACK_USER_TOKEN", "Slack User Token", re.compile(r"(?i)\bxoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32}\b"), Severity.CRITICAL),
    RegexRule("SLACK_WEBHOOK", "Slack Webhook URL", re.compile(r"(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"), Severity.CRITICAL),
    RegexRule("OPENAI_API_KEY", "OpenAI API Key", re.compile(r"(?i)\bsk-[a-zA-Z0-9]{48}\b"), Severity.CRITICAL),
    RegexRule("GOOGLE_GCP_API_KEY", "Google GCP API Key", re.compile(r"(?i)\bAIza[0-9A-Za-z\\-_]{35}\b"), Severity.CRITICAL),
    RegexRule("RSA_PRIVATE_KEY", "RSA Private Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----"), Severity.CRITICAL),
    RegexRule("PGP_PRIVATE_KEY", "PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----"), Severity.CRITICAL),
    RegexRule("DSA_PRIVATE_KEY", "DSA Private Key", re.compile(r"-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----"), Severity.CRITICAL),
    RegexRule("EC_PRIVATE_KEY", "EC Private Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----"), Severity.CRITICAL),
    RegexRule("OPENSSH_PRIVATE_KEY", "OpenSSH Private Key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----"), Severity.CRITICAL),
    RegexRule("PRIVATE_KEY_GENERIC", "Generic Private Key", re.compile(r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"), Severity.CRITICAL),
    RegexRule("POSTGRES_URI", "PostgreSQL URI", re.compile(r"(?i)postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+:\d+/[a-zA-Z0-9_]+"), Severity.HIGH),
    RegexRule("MONGO_URI", "MongoDB URI", re.compile(r"(?i)mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+"), Severity.HIGH),
    RegexRule("MYSQL_URI", "MySQL URI", re.compile(r"(?i)mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+:\d+/[a-zA-Z0-9_]+"), Severity.HIGH),
    RegexRule("REDIS_URI", "Redis URI", re.compile(r"(?i)redis(?:s)?://(?:[^@\s]+@)?[a-zA-Z0-9_.-]+:\d+"), Severity.MEDIUM),
    RegexRule("TWILIO_API_KEY", "Twilio API Key", re.compile(r"(?i)SK[0-9a-fA-F]{32}"), Severity.HIGH),
    RegexRule("SENDGRID_API_KEY", "SendGrid API Key", re.compile(r"(?i)SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"), Severity.HIGH),
    RegexRule("MAILGUN_API_KEY", "Mailgun API Key", re.compile(r"(?i)key-[0-9a-zA-Z]{32}"), Severity.HIGH),
    RegexRule("HEROKU_API_KEY", "Heroku API Key", re.compile(r"(?i)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), Severity.MEDIUM),
    RegexRule("SQUARE_ACCESS_TOKEN", "Square Access Token", re.compile(r"(?i)sq0atp-[0-9A-Za-z\-_]{22}"), Severity.HIGH),
    RegexRule("SQUARE_OAUTH_SECRET", "Square OAuth Secret", re.compile(r"(?i)sq0csp-[0-9A-Za-z\-_]{43}"), Severity.HIGH),
    RegexRule("DATADOG_ACCESS_TOKEN", "Datadog Access Token", re.compile(r"(?i)[a-zA-Z0-9_]{40}"), Severity.MEDIUM),
    RegexRule("DISCORD_BOT_TOKEN", "Discord Bot Token", re.compile(r"(?i)[a-zA-Z0-9_]{24}\.[a-zA-Z0-9_]{6}\.[a-zA-Z0-9_-]{27}"), Severity.HIGH),
    RegexRule("NPM_TOKEN", "NPM Token", re.compile(r"(?i)npm_[a-zA-Z0-9]{36}"), Severity.HIGH),
    RegexRule("PYPI_TOKEN", "PyPI Token", re.compile(r"pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,}"), Severity.HIGH)
]

class RegexScanner(BaseScanner):
    """Scans for secrets using regular expressions."""

    def __init__(self, rules: list[RegexRule] | None = None):
        self.rules = rules or REGEX_RULES

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            findings.extend(self.scan_line(file_path, line_num, line))
        return findings

    def scan_line(self, file_path: str, line_number: int, line_content: str) -> list[Finding]:
        # Skip lines marked as ignored
        if "envshield:ignore" in line_content.lower():
            return []

        findings = []
        for rule in self.rules:
            for match in rule.pattern.finditer(line_content):
                secret = match.group(0)
                # Some generic patterns might be too broad; we try to avoid some FPs by checking lengths 
                # but these rules are tailored for specific signatures where possible.
                finding = Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=rule.id,
                    description=f"Potential {rule.name} found.",
                    severity=rule.severity,
                    secret_value=mask_secret(secret),
                    remediation=f"Remove the hardcoded {rule.name} and use an environment variable or secret manager."
                )
                findings.append(finding)
        return findings
