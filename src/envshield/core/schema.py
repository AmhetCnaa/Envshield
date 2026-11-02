from __future__ import annotations

import ipaddress
import json
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

WEAK_SECRETS: set[str] = {
    "password",
    "123456",
    "12345678",
    "123456789",
    "admin",
    "secret",
    "qwerty",
    "root",
    "toor",
    "test",
    "default",
    "changeme",
    "letmein",
    "12345",
}

SECRET_KEY_KEYWORDS: tuple[str, ...] = (
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "API_KEY",
)


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy H(X) = -sum(p * log2(p)) of a string in bits per character.
    Returns 0.0 for empty or single-character repeated strings.
    """
    if not data or len(data) <= 1:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return max(0.0, round(entropy, 3))


@dataclass
class SchemaRule:
    key: str
    required: bool = True
    type_name: str = "string"  # int, port, bool, url, ipv4, json, email, uuid, string, secret
    min_length: int | None = None
    max_length: int | None = None
    min_entropy: float | None = None
    regex_pattern: str | None = None

    @classmethod
    def from_directive_str(cls, key: str, directive: str) -> SchemaRule:
        """
        Parses directives like:
          'required, type=port'
          'type=url, min_length=10'
          'type=secret, min_entropy=3.2'
        """
        rule = cls(key=key)
        tokens = [t.strip() for t in directive.split(",") if t.strip()]
        for tok in tokens:
            if tok.lower() == "required":
                rule.required = True
            elif tok.lower() == "optional":
                rule.required = False
            elif "=" in tok:
                k, v = [x.strip() for x in tok.split("=", 1)]
                kl = k.lower()
                if kl == "type":
                    rule.type_name = v.lower()
                elif kl == "min_length":
                    rule.min_length = int(v)
                elif kl == "max_length":
                    rule.max_length = int(v)
                elif kl in ("min_entropy", "entropy"):
                    rule.min_entropy = float(v)
                elif kl == "regex":
                    rule.regex_pattern = v
        return rule


@dataclass
class SchemaIssue:
    key: str
    message: str
    severity: str = "ERROR"  # ERROR or WARNING
    value_snippet: str = ""


@dataclass
class SchemaValidationReport:
    issues: list[SchemaIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(i.severity == "ERROR" for i in self.issues)

    @property
    def errors(self) -> list[SchemaIssue]:
        return [i for i in self.issues if i.severity == "ERROR"]

    @property
    def warnings(self) -> list[SchemaIssue]:
        return [i for i in self.issues if i.severity == "WARNING"]


def parse_schema_from_env_content(content: str) -> dict[str, SchemaRule]:
    """
    Parses inline schema directives from .env comments, e.g.:
      # @schema: required, type=port
      PORT=8080
    """
    rules: dict[str, SchemaRule] = {}
    pending_directive: str | None = None

    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        if trimmed.startswith("#") and "@schema:" in trimmed:
            pending_directive = trimmed.split("@schema:", 1)[1].strip()
            continue

        if pending_directive and "=" in trimmed and not trimmed.startswith("#"):
            key_part = trimmed.split("=", 1)[0].strip()
            # Clean export keyword
            if key_part.startswith("export "):
                key_part = key_part[7:].strip()
            rules[key_part] = SchemaRule.from_directive_str(key_part, pending_directive)
            pending_directive = None
        elif not trimmed.startswith("#"):
            pending_directive = None

    return rules


def parse_schema_file(schema_path: Path | str) -> dict[str, SchemaRule]:
    """
    Parses a dedicated .env.schema file (key=directives or JSON schema format).
    """
    p = Path(schema_path)
    if not p.is_file():
        return {}

    raw = p.read_text(encoding="utf-8").strip()
    rules: dict[str, SchemaRule] = {}

    # Try JSON schema format first
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            for k, v in data.items():
                if isinstance(v, str):
                    rules[k] = SchemaRule.from_directive_str(k, v)
                elif isinstance(v, dict):
                    rules[k] = SchemaRule(
                        key=k,
                        required=v.get("required", True),
                        type_name=v.get("type", "string"),
                        min_length=v.get("min_length"),
                        max_length=v.get("max_length"),
                        min_entropy=v.get("min_entropy"),
                        regex_pattern=v.get("regex"),
                    )
            return rules
        except Exception:
            pass

    # Fallback to key=directive lines
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, directive = line.split("=", 1)
            rules[k.strip()] = SchemaRule.from_directive_str(k.strip(), directive.strip())

    return rules


def _is_valid_url(val: str) -> bool:
    try:
        parsed = urlparse(val)
        return bool(parsed.scheme and (parsed.netloc or parsed.path))
    except Exception:
        return False


def _is_valid_email(val: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", val))


def _is_valid_ipv4(val: str) -> bool:
    try:
        ipaddress.IPv4Address(val)
        return True
    except Exception:
        return False


def _is_valid_json(val: str) -> bool:
    try:
        json.loads(val)
        return True
    except Exception:
        return False


def _is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False


def validate_single_secret(key: str, val: str | None, rule: SchemaRule | None = None) -> list[SchemaIssue]:
    """
    Validates a single key-value pair against an optional rule and universal entropy heuristics.
    """
    issues: list[SchemaIssue] = []
    val_snippet = (val[:4] + "..." + val[-2:]) if (val and len(val) > 8) else (val or "<empty>")

    # 1. Required check
    if (val is None or val == "") and rule and rule.required:
        issues.append(
            SchemaIssue(
                key=key,
                message=f"Required environment variable '{key}' is missing or empty.",
                severity="ERROR",
                value_snippet="<missing>",
            )
        )
        return issues

    if val is None or val == "":
        return issues

    # 2. Universal Entropy & Weak Secret Check for sensitive variable names
    upper_key = key.upper()
    is_sensitive = any(kw in upper_key for kw in SECRET_KEY_KEYWORDS) or (
        rule is not None and rule.type_name == "secret"
    )

    if is_sensitive:
        val_clean = val.strip().lower()
        if val_clean in WEAK_SECRETS:
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Secret '{key}' contains a known insecure common password ('{val_clean}').",
                    severity="ERROR",
                    value_snippet=val_snippet,
                )
            )

        entropy = calculate_shannon_entropy(val)
        required_entropy = (rule.min_entropy if (rule and rule.min_entropy is not None) else 3.0)
        if len(val) >= 6 and entropy < required_entropy:
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Secret '{key}' has dangerously low Shannon entropy ({entropy:.2f} < {required_entropy:.2f} bits/char).",
                    severity="WARNING",
                    value_snippet=val_snippet,
                )
            )

    # 3. Type validations if rule provided
    if rule:
        tn = rule.type_name.lower()
        if tn == "int":
            try:
                int(val)
            except ValueError:
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected integer for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "port":
            try:
                p = int(val)
                if not (1 <= p <= 65535):
                    issues.append(
                        SchemaIssue(
                            key=key,
                            message=f"Port for '{key}' must be between 1 and 65535 (got {p}).",
                            severity="ERROR",
                            value_snippet=val_snippet,
                        )
                    )
            except ValueError:
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected port number for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "bool":
            if val.lower() not in ("true", "false", "1", "0", "yes", "no"):
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected boolean (true/false/1/0) for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "url":
            if not _is_valid_url(val):
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected valid URL with scheme for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "ipv4":
            if not _is_valid_ipv4(val):
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected valid IPv4 address for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "json":
            if not _is_valid_json(val):
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected valid JSON payload for '{key}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "email":
            if not _is_valid_email(val):
                issues.append(
                    SchemaIssue(
                        key=key,
                        message=f"Expected valid email address for '{key}', got '{val}'.",
                        severity="ERROR",
                        value_snippet=val_snippet,
                    )
                )
        elif tn == "uuid" and not _is_valid_uuid(val):
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Expected valid UUID for '{key}', got '{val}'.",
                    severity="ERROR",
                    value_snippet=val_snippet,
                )
            )

        # Length constraints
        if rule.min_length is not None and len(val) < rule.min_length:
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Value for '{key}' is shorter than min_length {rule.min_length} (length: {len(val)}).",
                    severity="ERROR",
                    value_snippet=val_snippet,
                )
            )
        if rule.max_length is not None and len(val) > rule.max_length:
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Value for '{key}' exceeds max_length {rule.max_length} (length: {len(val)}).",
                    severity="ERROR",
                    value_snippet=val_snippet,
                )
            )

        # Regex constraint
        if rule.regex_pattern and not re.search(rule.regex_pattern, val):
            issues.append(
                SchemaIssue(
                    key=key,
                    message=f"Value for '{key}' does not match regex pattern '{rule.regex_pattern}'.",
                    severity="ERROR",
                    value_snippet=val_snippet,
                )
            )

    return issues


def validate_secrets_schema(
    secrets: dict[str, str],
    schema_rules: dict[str, SchemaRule] | None = None,
    raw_env_content: str | None = None,
    schema_path: Path | str | None = None,
) -> SchemaValidationReport:
    """
    Performs pre-flight in-memory validation of all environment variables against
    schema rules and entropy gatekeeper heuristics.
    """
    rules: dict[str, SchemaRule] = {}

    # 1. Load rules from .env.schema file if present
    if schema_path:
        rules.update(parse_schema_file(schema_path))
    else:
        # Check standard default .env.schema file in current working directory
        default_schema = Path(".env.schema")
        if default_schema.is_file():
            rules.update(parse_schema_file(default_schema))

    # 2. Load inline schema comments from raw .env content
    if raw_env_content:
        rules.update(parse_schema_from_env_content(raw_env_content))

    # 3. Explicit rules override
    if schema_rules:
        rules.update(schema_rules)

    report = SchemaValidationReport()

    # Check all schema rules (including missing required keys)
    for k, rule in rules.items():
        val = secrets.get(k)
        issues = validate_single_secret(k, val, rule)
        report.issues.extend(issues)

    # Check all secrets not covered by explicit rules for universal entropy/passwords
    for k, v in secrets.items():
        if k not in rules:
            issues = validate_single_secret(k, v, None)
            report.issues.extend(issues)

    return report
