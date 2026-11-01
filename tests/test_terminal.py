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
