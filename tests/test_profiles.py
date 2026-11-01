from __future__ import annotations

import pytest

from envshield.core.profiles import (
    ProfileNotFoundError,
    detect_git_branch_profile,
    list_profiles,
    parse_profiled_env,
    parse_secrets_with_profile,
)

SAMPLE_PROFILED_ENV = """
APP_NAME=GlobalShield
PORT=8080

[development]
DEBUG=true
DB_URL=postgres://localhost:5432/dev_db
PORT=3000

[production]
DEBUG=false
DB_URL=postgres://prod-db.internal:5432/prod_db
"""


def test_list_profiles() -> None:
    profiles = list_profiles(SAMPLE_PROFILED_ENV, format_type="env")
    assert "development" in profiles
    assert "production" in profiles


def test_parse_profiled_env_default() -> None:
    secrets = parse_profiled_env(SAMPLE_PROFILED_ENV, profile=None)
    assert secrets["APP_NAME"] == "GlobalShield"
    assert secrets["PORT"] == "8080"
    assert "DEBUG" not in secrets


def test_parse_profiled_env_dev() -> None:
    secrets = parse_profiled_env(SAMPLE_PROFILED_ENV, profile="development")
    assert secrets["APP_NAME"] == "GlobalShield"
    assert secrets["DEBUG"] == "true"
    assert secrets["PORT"] == "3000"  # Overridden by development
    assert secrets["DB_URL"] == "postgres://localhost:5432/dev_db"


def test_parse_profiled_env_prod() -> None:
    secrets = parse_profiled_env(SAMPLE_PROFILED_ENV, profile="production")
    assert secrets["APP_NAME"] == "GlobalShield"
    assert secrets["DEBUG"] == "false"
    assert secrets["PORT"] == "8080"  # Kept from default
    assert secrets["DB_URL"] == "postgres://prod-db.internal:5432/prod_db"


def test_parse_profiled_env_not_found() -> None:
    with pytest.raises(ProfileNotFoundError):
        parse_profiled_env(SAMPLE_PROFILED_ENV, profile="nonexistent")


def test_parse_flat_env_backward_compat() -> None:
    flat = "FOO=bar\nBAZ=qux\n"
    secrets = parse_secrets_with_profile(flat, profile=None)
    assert secrets["FOO"] == "bar"
    assert secrets["BAZ"] == "qux"


def test_detect_git_branch_profile(monkeypatch) -> None:
    # Test fallback
    prof = detect_git_branch_profile()
    assert prof in ("development", "staging", "production")
