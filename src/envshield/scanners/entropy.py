import math
import re

from envshield.core.base import BaseScanner
from envshield.core.models import Finding, Severity
from envshield.utils.masking import mask_secret


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = {char: data.count(char) for char in set(data)}

    for count in occurrences.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


class EntropyScanner(BaseScanner):
    """Scans for high-entropy strings which often represent cryptographic keys or passwords."""

    def __init__(self, min_length: int = 16, entropy_threshold: float = 4.5):
        self.min_length = min_length
        self.entropy_threshold = entropy_threshold
        # Find potential strings: anything alphanumeric with some special chars that is long enough
        self.string_pattern = re.compile(r"[A-Za-z0-9+/=_-]{" + str(self.min_length) + r",}")

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            findings.extend(self.scan_line(file_path, line_num, line))
        return findings

    def scan_line(self, file_path: str, line_number: int, line_content: str) -> list[Finding]:
        if "envshield:ignore" in line_content.lower():
            return []

        findings = []
        for match in self.string_pattern.finditer(line_content):
            candidate = match.group(0)
            entropy = shannon_entropy(candidate)
            if entropy > self.entropy_threshold:
                finding = Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id="HIGH_ENTROPY_STRING",
                    description=f"High entropy string detected (entropy: {entropy:.2f}).",
                    severity=Severity.MEDIUM,
                    secret_value=mask_secret(candidate),
                    remediation="Verify if this is a hardcoded secret. If so, move it to a secret manager.",
                )
                findings.append(finding)
        return findings
