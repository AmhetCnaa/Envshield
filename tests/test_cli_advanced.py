from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

from envshield.cli.main import main
from envshield.core.vault import seal_file


def my_exit(code=0):
    raise SystemExit(code)


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_audit_list_and_verify(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    audit_file = tmp_path / "test.audit.jsonl"
    monkeypatch.setenv("ENVSHIELD_AUDIT_FILE", str(audit_file))

    # Create dummy env & seal it
    env_file = tmp_path / ".env"
    env_file.write_text("API_SECRET=super123\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "pass123")

    # 1. Audit list
    with pytest.raises(SystemExit) as exc:
        main(["audit", "list"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "SEAL" in out

    # 2. Audit verify
    with pytest.raises(SystemExit) as exc:
        main(["audit", "verify"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "verified successfully" in out


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_hook_install_and_uninstall(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    # Install hook
    with pytest.raises(SystemExit) as exc:
        main(["hook", "install"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "installed" in out.lower()

    # Uninstall hook
    with pytest.raises(SystemExit) as exc:
        main(["hook", "uninstall"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "uninstalled" in out.lower()


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_with_profile(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    env_content = """
APP=DefaultApp
[production]
DB_PORT=5432
[development]
DB_PORT=3306
"""
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "mypass")

    monkeypatch.setenv("ENVSHIELD_KEY", "mypass")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "run",
                "--profile",
                "production",
                "--",
                sys.executable,
                "-c",
                "import os; print(f'PORT:{os.environ.get(\"DB_PORT\")}')",
            ]
        )
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "PORT:[REDACTED:DB_PORT]" in out

    # Test with --no-redact to verify unmasked value
    with pytest.raises(SystemExit) as exc_raw:
        main(
            [
                "run",
                "--profile",
                "production",
                "--no-redact",
                "--",
                sys.executable,
                "-c",
                "import os; print(f'PORT:{os.environ.get(\"DB_PORT\")}')",
            ]
        )
    assert exc_raw.value.code == 0
    out_raw, _ = capfd.readouterr()
    assert "PORT:5432" in out_raw


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_decoy_fallback(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("REAL_SECRET=true_classified\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "right_password")

    # Pass WRONG password with --enable-decoy
    monkeypatch.setenv("ENVSHIELD_KEY", "wrong_password")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "run",
                "--enable-decoy",
                "--",
                sys.executable,
                "-c",
                "import os; print(f'HONEY:{os.environ.get(\"HONEYPOT_ACTIVE\")}')",
            ]
        )
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "HONEY:true" in out
    assert "Warning: Access restricted" in out
