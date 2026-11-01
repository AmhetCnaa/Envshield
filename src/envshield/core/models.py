from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """Represents a single security or environment validation finding."""

    file_path: str
    line_number: int
    rule_id: str
    description: str
    severity: Severity
    secret_value: str | None = None  # Store masked value, not raw if possible
    remediation: str = "Review the finding and remediate if necessary."


@dataclass
class ScanResult:
    """Contains all findings from a scan execution."""

    findings: list[Finding] = field(default_factory=list)
    scanned_files_count: int = 0

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def has_issues(self) -> bool:
        return len(self.findings) > 0
