from __future__ import annotations

from pathlib import Path

from envshield.core.runner import execute_with_env
from envshield.core.schema import (
    SchemaRule,
    calculate_shannon_entropy,
    parse_schema_file,
    parse_schema_from_env_content,
    validate_secrets_schema,
)


def test_shannon_entropy_values() -> None:
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("a") == 0.0
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    assert calculate_shannon_entropy("123456") < 3.0
    assert calculate_shannon_entropy("password") < 3.0

    high_ent = calculate_shannon_entropy("k9#Xm$8P@2qZ!wL&vR4^bN7*")
    assert high_ent >= 4.0


def test_weak_secret_detection() -> None:
    secrets = {
        "DATABASE_PASSWORD": "password",
        "API_SECRET_KEY": "123456",
        "AUTH_TOKEN": "admin",
    }
    rep = validate_secrets_schema(secrets)
    assert not rep.is_valid
    messages = [e.message for e in rep.errors]
    assert any("insecure common password ('password')" in m for m in messages)
    assert any("insecure common password ('123456')" in m for m in messages)
    assert any("insecure common password ('admin')" in m for m in messages)


def test_type_validations() -> None:
    rules = {
        "PORT": SchemaRule(key="PORT", type_name="port"),
        "URL": SchemaRule(key="URL", type_name="url"),
        "FLAG": SchemaRule(key="FLAG", type_name="bool"),
        "IP": SchemaRule(key="IP", type_name="ipv4"),
        "PAYLOAD": SchemaRule(key="PAYLOAD", type_name="json"),
        "EMAIL": SchemaRule(key="EMAIL", type_name="email"),
        "UID": SchemaRule(key="UID", type_name="uuid"),
    }

    # Test valid inputs
    good_secrets = {
        "PORT": "8443",
        "URL": "https://api.envshield.dev/v1",
        "FLAG": "true",
        "IP": "192.168.1.1",
        "PAYLOAD": '{"status": "ok"}',
        "EMAIL": "ops@envshield.dev",
        "UID": "12345678-1234-5678-1234-567812345678",
    }
    rep_good = validate_secrets_schema(good_secrets, schema_rules=rules)
    assert rep_good.is_valid

    # Test invalid inputs
    bad_secrets = {
        "PORT": "70000",
        "URL": "not_a_valid_url",
        "FLAG": "maybe",
        "IP": "999.999.999.999",
        "PAYLOAD": "{bad_json",
        "EMAIL": "invalid_email_at_nowhere",
        "UID": "not-a-uuid",
    }
    rep_bad = validate_secrets_schema(bad_secrets, schema_rules=rules)
    assert not rep_bad.is_valid
    assert len(rep_bad.errors) == 7


def test_directive_parsing_from_env_comments() -> None:
    raw_env = """
    # Normal comment
    APP_NAME=my_app

    # @schema: required, type=port
    APP_PORT=3000

    # @schema: type=url, min_length=10
    DATABASE_URL=postgres://localhost:5432/db
    """
    rules = parse_schema_from_env_content(raw_env)
    assert "APP_PORT" in rules
    assert rules["APP_PORT"].type_name == "port"
    assert rules["APP_PORT"].required is True

    assert "DATABASE_URL" in rules
    assert rules["DATABASE_URL"].type_name == "url"
    assert rules["DATABASE_URL"].min_length == 10


def test_schema_file_parsing(tmp_path: Path) -> None:
    schema_file = tmp_path / ".env.schema"
    schema_file.write_text(
        "REDIS_PORT=required, type=port\n"
        "BACKEND_URL=required, type=url\n"
        "CACHE_TTL=type=int\n",
        encoding="utf-8",
    )
    rules = parse_schema_file(schema_file)
    assert len(rules) == 3
    assert rules["REDIS_PORT"].type_name == "port"
    assert rules["BACKEND_URL"].type_name == "url"
    assert rules["CACHE_TTL"].type_name == "int"


def test_runner_preflight_strict_schema_blocking(tmp_path: Path) -> None:
    schema_file = tmp_path / ".env.schema"
    schema_file.write_text("SERVICE_PORT=required, type=port\n", encoding="utf-8")

    # Invalid port (abc) with strict_schema=True should abort before execution
    invalid_secrets = {"SERVICE_PORT": "not_a_port"}
    exit_code = execute_with_env(
        ["python", "-c", "print('should not run')"],
        invalid_secrets,
        strict_schema=True,
        schema_path=schema_file,
    )
    assert exit_code == 1
