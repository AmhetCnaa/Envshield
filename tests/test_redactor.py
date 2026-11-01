from __future__ import annotations

import io
import sys

from envshield.core.redactor import SecretRedactor
from envshield.core.runner import execute_with_env


def test_secret_redactor_basic() -> None:
    secrets = {
        "API_KEY": "sk_live_supersecret987",
        "DB_PASS": "my_db_password_xyz",
        "DEBUG": "true",  # Should not be redacted (common word)
    }
    redactor = SecretRedactor(secrets)

    text = "Starting app with DB password my_db_password_xyz and key sk_live_supersecret987, debug=true"
    redacted = redactor.redact_text(text)

    assert "[REDACTED:DB_PASS]" in redacted
    assert "[REDACTED:API_KEY]" in redacted
    assert "my_db_password_xyz" not in redacted
    assert "sk_live_supersecret987" not in redacted
    assert "debug=true" in redacted


def test_secret_redactor_stream_pipe() -> None:
    secrets = {"TOKEN": "topsecrettoken123"}
    redactor = SecretRedactor(secrets)

    pipe_in = io.StringIO(
        "Connecting to server...\nAuth failed: token=topsecrettoken123 is invalid\nDone.\n"
    )
    pipe_out = io.StringIO()

    redactor.stream_pipe(pipe_in, pipe_out)
    output = pipe_out.getvalue()

    assert "topsecrettoken123" not in output
    assert "[REDACTED:TOKEN]" in output
    assert "Connecting to server..." in output


def test_execute_with_env_redaction(monkeypatch) -> None:
    # Test that running python print(secret) gets redacted in stream
    out_buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out_buf)

    code = "import os; print(f'FOUND: {os.environ.get(\"SUPER_KEY\")}')"
    cmd = [sys.executable, "-c", code]
    secrets = {"SUPER_KEY": "super_secret_payload_1234"}

    exit_code = execute_with_env(cmd, secrets, redact=True)
    assert exit_code == 0
    captured = out_buf.getvalue()
    assert "super_secret_payload_1234" not in captured
    assert "[REDACTED:SUPER_KEY]" in captured


def test_execute_with_env_no_redact(monkeypatch) -> None:
    out_buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out_buf)

    code = "import os; print(f'RAW: {os.environ.get(\"RAW_KEY\")}')"
    cmd = [sys.executable, "-c", code]
    secrets = {"RAW_KEY": "unredacted_secret_value"}

    exit_code = execute_with_env(cmd, secrets, redact=False)
    assert exit_code == 0
