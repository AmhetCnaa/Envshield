from envshield.core.models import Severity
from envshield.scanners.entropy import EntropyScanner, shannon_entropy
from envshield.scanners.env_validator import EnvValidator
from envshield.scanners.regex import RegexScanner


def test_regex_scanner_aws_key():
    scanner = RegexScanner()
    content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
    findings = scanner.scan_file("test.py", content)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS_ACCESS_KEY"
    assert findings[0].severity == Severity.CRITICAL


def test_regex_scanner_ignore_inline():
    scanner = RegexScanner()
    content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE # envshield:ignore\n"
    findings = scanner.scan_file("test.py", content)
    assert len(findings) == 0


def test_entropy_scanner():
    scanner = EntropyScanner(min_length=16, entropy_threshold=4.0)
    # High entropy string
    content = "secret = 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'\n"
    findings = scanner.scan_file("test.py", content)
    assert len(findings) == 1
    assert findings[0].rule_id == "HIGH_ENTROPY_STRING"


def test_entropy_scanner_ignore():
    scanner = EntropyScanner(min_length=16, entropy_threshold=4.0)
    content = "secret = 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z' # envshield:ignore\n"
    findings = scanner.scan_file("test.py", content)
    assert len(findings) == 0


def test_shannon_entropy():
    # AAA has entropy 0
    assert shannon_entropy("AAA") == 0.0
    # ABC has entropy ~1.58
    assert shannon_entropy("ABC") > 1.5


def test_env_validator_missing_var():
    validator = EnvValidator()
    example = "PORT=8080\nAPI_KEY=xxx"
    env = "PORT=8080"
    findings = validator.validate(".env", env, ".env.example", example)
    assert len(findings) == 1
    assert findings[0].rule_id == "MISSING_ENV_VAR"
    assert "API_KEY" in findings[0].description


def test_env_validator_type_mismatch():
    validator = EnvValidator()
    example = "PORT=8080"
    env = "PORT=abc"
    findings = validator.validate(".env", env, ".env.example", example)
    assert len(findings) == 1
    assert findings[0].rule_id == "ENV_TYPE_MISMATCH"


def test_env_validator_extraneous_var():
    validator = EnvValidator()
    example = "PORT=8080"
    env = "PORT=8080\nEXTRA=123"
    findings = validator.validate(".env", env, ".env.example", example)
    assert len(findings) == 1
    assert findings[0].rule_id == "EXTRANEOUS_ENV_VAR"
