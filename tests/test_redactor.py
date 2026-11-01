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


def test_secret_redactor_chunk_boundary_sliding_window() -> None:
    """Verify secrets split across two arbitrary read() chunks are still caught."""
    secrets = {"STRIPE_KEY": "sk_live_9876543210abcdef"}
    redactor = SecretRedactor(secrets)

    # Split "sk_live_9876543210abcdef" across two chunks
    out1 = redactor.redact_chunk("Payment init with key=sk_li", is_eof=False)
    out2 = redactor.redact_chunk("ve_9876543210abcdef completed!\n", is_eof=True)
    combined = out1 + out2

    assert "sk_live_9876543210abcdef" not in combined
    assert "[REDACTED:STRIPE_KEY]" in combined
    assert "Payment init with key=" in combined
    assert " completed!\n" in combined


def test_secret_redactor_base64_and_urlencoded_variants() -> None:
    """Verify Base64-encoded and URL-encoded leaks are automatically redacted."""
    import base64
    import urllib.parse

    raw_secret = "p@ssw0rd/with+special=chars!"
    secrets = {"DB_SECRET": raw_secret}
    redactor = SecretRedactor(secrets)

    b64_secret = base64.b64encode(raw_secret.encode("utf-8")).decode("ascii")
    url_secret = urllib.parse.quote(raw_secret, safe="")

    log_line = f"Auth header: Basic {b64_secret} | Redirect: ?token={url_secret}"
    redacted = redactor.redact_text(log_line)

    assert b64_secret not in redacted
    assert url_secret not in redacted
    assert redacted.count("[REDACTED:DB_SECRET]") == 2


def test_secret_redactor_no_nested_double_redaction() -> None:
    """
    Verify that when a secret contains 'REDACTED' or 'KEY' or sits near the sliding window
    boundary, `redact_chunk` never double-redacts `[REDACTED:KEY]` into `[REDACTED:[REDACTED:KEY]]`.
    """
    secrets = {
        "TOKEN_A": "REDACTED",
        "LONG_KEY": "super_long_secret_value_for_lookahead_window_99999",
    }
    redactor = SecretRedactor(secrets)

    # First chunk contains a complete match for TOKEN_A ("REDACTED") without a trailing newline,
    # while LONG_KEY forces a 49-char lookahead window.
    chunk1 = "Status: REDACTED is the token, waiting for more..."
    chunk2 = " and here is the rest of the stream!\n"

    out1 = redactor.redact_chunk(chunk1, is_eof=False)
    out2 = redactor.redact_chunk(chunk2, is_eof=True)
    full = out1 + out2

    assert "[REDACTED:[REDACTED:" not in full
    assert full.count("[REDACTED:TOKEN_A]") == 1
    assert "Status: [REDACTED:TOKEN_A] is the token, waiting for more... and here is the rest of the stream!\n" == full

    redactor.close()
    assert len(redactor.val_to_key) == 0
    assert redactor.pattern is None



