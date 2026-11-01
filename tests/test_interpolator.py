from __future__ import annotations

import pytest

from envshield.core.interpolator import (
    CircularDependencyError,
    interpolate_secrets,
)


def test_interpolate_simple_reference() -> None:
    raw = {
        "HOST": "127.0.0.1",
        "PORT": "5432",
        "DB_URL": "postgresql://${HOST}:${PORT}/mydb",
    }
    resolved = interpolate_secrets(raw)
    assert resolved["DB_URL"] == "postgresql://127.0.0.1:5432/mydb"


def test_interpolate_with_defaults() -> None:
    raw = {
        "PORT": "${CUSTOM_PORT:-8080}",
        "SERVICE_URL": "https://api.internal:${PORT}/v1",
    }
    resolved = interpolate_secrets(raw)
    assert resolved["PORT"] == "8080"
    assert resolved["SERVICE_URL"] == "https://api.internal:8080/v1"


def test_interpolate_host_env_fallback(monkeypatch) -> None:
    monkeypatch.setenv("SYSTEM_USER", "antigravity_admin")
    raw = {
        "GREETING": "Hello, ${SYSTEM_USER}!",
    }
    resolved = interpolate_secrets(raw)
    assert resolved["GREETING"] == "Hello, antigravity_admin!"


def test_circular_dependency_detection() -> None:
    raw = {
        "A": "${B}",
        "B": "${C}",
        "C": "${A}",
    }
    with pytest.raises(CircularDependencyError) as exc_info:
        interpolate_secrets(raw)
    assert "Circular dependency detected" in str(exc_info.value)


def test_escaped_variable_literal() -> None:
    raw = {
        "NORMAL": "value",
        "ESCAPED": r"Price is \${NORMAL}",
    }
    resolved = interpolate_secrets(raw)
    assert resolved["ESCAPED"] == "Price is ${NORMAL}"
