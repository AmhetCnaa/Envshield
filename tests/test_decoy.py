from __future__ import annotations

from pathlib import Path

from envshield.core.audit import read_audit_entries
from envshield.core.decoy import (
    generate_default_canary_secrets,
    load_decoy_secrets,
    trigger_canary_alert,
    validate_webhook_url,
)


def test_generate_default_canary_secrets() -> None:
    canary = generate_default_canary_secrets()
    assert canary["HONEYPOT_ACTIVE"] == "true"
    assert "DATABASE_URL" in canary
    assert "API_KEY" in canary


def test_load_decoy_custom_file(tmp_path: Path) -> None:
    decoy_file = tmp_path / "custom.decoy.env"
    decoy_file.write_text("FAKE_VAR=12345\nTRAP=true\n", encoding="utf-8")

    secrets = load_decoy_secrets(decoy_file)
    assert secrets["FAKE_VAR"] == "12345"
    assert secrets["TRAP"] == "true"


def test_trigger_canary_alert(tmp_path: Path, monkeypatch) -> None:
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ENVSHIELD_AUDIT_FILE", str(audit_log))

    trigger_canary_alert(
        tmp_path / ".env.enc", webhook_url=None, details={"reason": "bad_password"}
    )

    entries = read_audit_entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["action"] == "DECOY_TRIGGERED"
    assert entries[0]["details"]["reason"] == "bad_password"


def test_validate_webhook_url_ssrf_protection() -> None:
    assert validate_webhook_url("https://hooks.slack.com/services/T00/B00/X00") is True
    assert validate_webhook_url("http://127.0.0.1:8080/alert") is True
    assert validate_webhook_url("file:///etc/passwd") is False
    assert validate_webhook_url("ftp://internal.corp/secret") is False
    assert validate_webhook_url("gopher://127.0.0.1:25/") is False
    assert validate_webhook_url("https://") is False

