import json
from typing import Any

from envshield.core.models import ScanResult


def format_json(result: ScanResult) -> str:
    """Formats the scan result as JSON."""
    data = {
        "scanned_files_count": result.scanned_files_count,
        "findings_count": len(result.findings),
        "findings": [
            {
                "file_path": f.file_path,
                "line_number": f.line_number,
                "rule_id": f.rule_id,
                "description": f.description,
                "severity": f.severity.value,
                "secret_value_masked": f.secret_value,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2)


def format_sarif(result: ScanResult) -> str:
    """Formats the scan result as SARIF."""
    # Build a simple SARIF representation
    rules: dict[str, Any] = {}
    results = []

    for finding in result.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
            }

        sarif_level = "warning"
        if finding.severity.value in ("HIGH", "CRITICAL"):
            sarif_level = "error"

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": sarif_level,
                "message": {
                    "text": f"{finding.description} (Masked secret: {finding.secret_value})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": finding.line_number or 1},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "envshield",
                        "informationUri": "https://github.com/example/envshield",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
