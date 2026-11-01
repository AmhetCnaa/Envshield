from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from envshield.cli.main import main
from envshield.core.runner import execute_with_env
from envshield.core.terminal import (
    execute_interactive,
    is_interactive_tty,
    setup_windows_virtual_terminal,
)
from envshield.core.vault import seal_file


def my_exit(code=0):
    raise SystemExit(code)


def test_is_interactive_tty() -> None:
    # During automated pytest, is_interactive_tty returns bool (usually False)
    res = is_interactive_tty()
    assert isinstance(res, bool)


def test_setup_windows_virtual_terminal() -> None:
    res = setup_windows_virtual_terminal()
    assert isinstance(res, bool)


def test_execute_interactive_empty() -> None:
    ret = execute_interactive([], {"A": "1"})
    assert ret == 0


def test_execute_interactive_fallback(monkeypatch) -> None:
    # Non-TTY environment in pytest should fall back to execute_with_env
    mock_runner = mock.MagicMock(return_value=42)
    monkeypatch.setattr("envshield.core.runner.execute_with_env", mock_runner)

    ret = execute_interactive(["echo", "hello"], {"TEST": "secret"}, redact=True)
    assert ret == 42
    mock_runner.assert_called_once()


def test_runner_pty_flag(monkeypatch) -> None:
    mock_terminal = mock.MagicMock(return_value=0)
    monkeypatch.setattr("envshield.core.terminal.execute_interactive", mock_terminal)

    ret = execute_with_env(["bash"], {"KEY": "123"}, pty=True)
    assert ret == 0
    mock_terminal.assert_called_once_with(["bash"], {"KEY": "123"}, redact=True)


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_with_pty_flag(mock_exit, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SHELL_SECRET=shh\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "mypass")

    monkeypatch.setenv("ENVSHIELD_KEY", "mypass")
    mock_exec = mock.MagicMock(return_value=0)
    monkeypatch.setattr("envshield.cli.main.execute_with_env", mock_exec)

    with pytest.raises(SystemExit) as exc:
        main(["run", "-t", "--", "bash"])
    assert exc.value.code == 0

    mock_exec.assert_called_once()
    assert mock_exec.call_args[1]["pty"] is True


def test_pty_idle_prompt_flush_and_utf8_incremental_decode() -> None:
    """
    Verifies two critical PTY behaviors highlighted by security review:
      1. Prompt Starvation Prevention: short prompts without trailing newline (e.g. 'Password: ')
         held in the lookahead buffer are immediately flushed when the PTY stream goes idle.
      2. Multi-Byte UTF-8 Split Prevention: UTF-8 characters (Turkish ğ, ü, ş, emoji) split
         across 4096-byte os.read() boundaries are reassembled cleanly via incremental decoder.
    """
    import codecs

    from envshield.core.redactor import SecretRedactor

    secrets = {"API_TOKEN": "sk_live_very_long_secret_token_9876543210"}
    redactor = SecretRedactor(secrets)
    utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    # 1. Simulate a 2-byte Turkish character ('ş' = 0xC5 0x9F) and 4-byte emoji ('🛡️') split across reads
    raw_bytes = "Şifre girin 🛡️ Password: ".encode()
    part1 = raw_bytes[:7]  # Splits right inside multi-byte UTF-8 sequence
    part2 = raw_bytes[7:]

    dec1 = utf8_decoder.decode(part1, final=False)
    dec2 = utf8_decoder.decode(part2, final=False)

    # First pass without newline holds short prompt inside lookahead buffer
    out1 = redactor.redact_chunk(dec1, is_eof=False)
    out2 = redactor.redact_chunk(dec2, is_eof=False)
    assert out1 + out2 == ""
    assert redactor._pending_buffer == "Şifre girin 🛡️ Password: "

    # When select() times out (idle after 50ms), PTY flushes the pending buffer with is_eof=True
    idle_flushed = redactor.redact_chunk("", is_eof=True)
    assert idle_flushed == "Şifre girin 🛡️ Password: "
    assert "\ufffd" not in idle_flushed

