from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

from envshield.cli.main import main
from envshield.core.runner import execute_with_env
from envshield.core.vault import (
    AuthError,
    InvalidKey,
    seal_file,
    shred_file,
    unseal_to_memory,
)


def my_exit(code=0):
    raise SystemExit(code)


def test_seal_and_unseal_correct_password(tmp_path: Path):
    """Verifies that an environment file is encrypted and correctly parsed in RAM."""
    env_file = tmp_path / ".env"
    enc_file = tmp_path / ".env.enc"
    password = "CorrectHorseBatteryStaple123!"

    env_content = (
        "# Database configuration\n"
        "DB_HOST=127.0.0.1\n"
        "DB_PORT=5432\n"
        'DB_USER="postgres"\n'
        "DB_PASS='super#secret=complex'\n"
        "export API_KEY=sk_live_999888\n"
        "EMPTY_VALUE=\n"
    )
    env_file.write_text(env_content, encoding="utf-8")

    # Seal the file
    seal_file(env_file, enc_file, password)

    assert enc_file.is_file()
    enc_bytes = enc_file.read_bytes()
    assert len(enc_bytes) > len(env_content)
    # Plaintext must never be present in the encrypted payload
    assert b"sk_live_999888" not in enc_bytes
    assert b"postgres" not in enc_bytes

    # Unseal directly into RAM
    secrets = unseal_to_memory(enc_file, password)

    assert isinstance(secrets, dict)
    assert secrets["DB_HOST"] == "127.0.0.1"
    assert secrets["DB_PORT"] == "5432"
    assert secrets["DB_USER"] == "postgres"
    assert secrets["DB_PASS"] == "super#secret=complex"
    assert secrets["API_KEY"] == "sk_live_999888"
    assert secrets["EMPTY_VALUE"] == ""


def test_unseal_wrong_password_raises_invalid_key_and_auth_error(tmp_path: Path):
    """Verifies that an incorrect password raises InvalidKey (and AuthError)."""
    env_file = tmp_path / ".env"
    enc_file = tmp_path / ".env.enc"
    env_file.write_text("SECRET_KEY=123456\n", encoding="utf-8")

    seal_file(env_file, enc_file, "correct_password")

    # Test InvalidKey
    with pytest.raises(InvalidKey):
        unseal_to_memory(enc_file, "wrong_password")

    # Test AuthError (since InvalidKey is an AuthError subclass)
    with pytest.raises(AuthError):
        unseal_to_memory(enc_file, "wrong_password")


def test_unseal_corrupted_payload(tmp_path: Path):
    """Verifies that corrupted or truncated encrypted files raise AuthError."""
    enc_file = tmp_path / ".env.enc"
    # File too short
    enc_file.write_bytes(b"shortpayload")
    with pytest.raises(AuthError):
        unseal_to_memory(enc_file, "any_password")

    # File with tampered ciphertext
    valid_env = tmp_path / ".env"
    valid_env.write_text("SECRET=abc\n", encoding="utf-8")
    seal_file(valid_env, enc_file, "password")

    data = bytearray(enc_file.read_bytes())
    # Tamper with the ciphertext/tag
    data[-1] ^= 0xFF
    enc_file.write_bytes(bytes(data))

    with pytest.raises(AuthError):
        unseal_to_memory(enc_file, "password")


def test_vault_file_not_found(tmp_path: Path):
    """Verifies FileNotFoundError when source file does not exist."""
    with pytest.raises(FileNotFoundError):
        seal_file(tmp_path / "nonexistent.env", tmp_path / "out.enc", "pass")

    with pytest.raises(FileNotFoundError):
        unseal_to_memory(tmp_path / "nonexistent.enc", "pass")


def test_vault_invalid_utf8(tmp_path: Path):
    """Verifies AuthError when decrypted content is not valid UTF-8."""
    env_file = tmp_path / "invalid.bin"
    enc_file = tmp_path / "invalid.bin.enc"
    # Write invalid UTF-8 byte sequence
    env_file.write_bytes(b"\x80\x81\x82\x83")

    seal_file(env_file, enc_file, "testpass")
    with pytest.raises(AuthError, match="not valid UTF-8"):
        unseal_to_memory(enc_file, "testpass")


def test_execute_with_env_subprocess_injection(capfd):
    """Verifies that execute_with_env passes injected secrets directly to child subprocess."""
    command = [
        sys.executable,
        "-c",
        "import os; print(os.environ['TEST_KEY'])",
    ]
    secrets = {"TEST_KEY": "CONFIDENTIAL_INJECTED_VALUE_42"}

    exit_code = execute_with_env(command, secrets)
    assert exit_code == 0

    out, _ = capfd.readouterr()
    assert "CONFIDENTIAL_INJECTED_VALUE_42" in out


def test_execute_with_env_empty_and_nonzero():
    """Verifies edge cases for execute_with_env (empty command and non-zero exit codes)."""
    assert execute_with_env([], {"A": "1"}) == 0

    command = [sys.executable, "-c", "import sys; sys.exit(7)"]
    assert execute_with_env(command, {}) == 7


def test_shred_file(tmp_path: Path):
    """Verifies that shred_file overwrites and removes the file."""
    secret_file = tmp_path / ".env"
    secret_file.write_text("SENSITIVE_DATA_12345", encoding="utf-8")
    assert secret_file.exists()

    shred_file(secret_file)
    assert not secret_file.exists()

    # Shredding a non-existent file shouldn't raise
    shred_file(tmp_path / "already_deleted.env")


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_seal_and_run_end_to_end(mock_exit, tmp_path: Path, monkeypatch, capfd):
    """End-to-end test for 'envshield seal' and 'envshield run -- [COMMAND]' via CLI."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("APP_TOKEN=token_cli_999\n", encoding="utf-8")

    # 1. Test CLI seal with password prompt mocked
    with mock.patch("getpass.getpass", return_value="test_password"), pytest.raises(SystemExit) as exc_seal:
        main(["seal"])
    assert exc_seal.value.code == 0

    enc_file = tmp_path / ".env.enc"
    assert enc_file.is_file()

    # 2. Test CLI run with ENVSHIELD_KEY environment variable
    monkeypatch.setenv("ENVSHIELD_KEY", "test_password")
    with pytest.raises(SystemExit) as exc_run:
        main([
            "run",
            "--",
            sys.executable,
            "-c",
            "import os; print(os.environ['APP_TOKEN'])",
        ])
    assert exc_run.value.code == 0

    out, _ = capfd.readouterr()
    assert "token_cli_999" in out


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_without_double_dash(mock_exit, tmp_path: Path, monkeypatch, capfd):
    """Verifies 'envshield run' without explicit '--' separator."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("DIRECT_VAR=direct_ok\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "direct_pass")

    monkeypatch.setenv("ENVSHIELD_KEY", "direct_pass")
    with pytest.raises(SystemExit) as exc_run:
        main([
            "run",
            sys.executable,
            "-c",
            "import os; print(os.environ['DIRECT_VAR'])",
        ])
    assert exc_run.value.code == 0

    out, _ = capfd.readouterr()
    assert "direct_ok" in out


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_seal_with_shred(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies 'envshield seal --shred' deletes the original .env file."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("TEMP_KEY=abc\n", encoding="utf-8")

    monkeypatch.setenv("ENVSHIELD_KEY", "shred_pass")
    with pytest.raises(SystemExit) as exc:
        main(["seal", "--shred"])
    assert exc.value.code == 0

    assert (tmp_path / ".env.enc").is_file()
    assert not env_file.exists()


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_seal_missing_file_fails(mock_exit, tmp_path: Path):
    """Verifies 'envshield seal' fails if source file does not exist."""
    with pytest.raises(SystemExit) as exc:
        main(["seal", str(tmp_path / "missing.env")])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_seal_empty_password_fails(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies 'envshield seal' fails if password entered is empty."""
    monkeypatch.delenv("ENVSHIELD_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")

    with mock.patch("getpass.getpass", return_value=""), pytest.raises(SystemExit) as exc:
        main(["seal", str(env_file)])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_missing_env_file_fails(mock_exit, tmp_path: Path):
    """Verifies 'envshield run' fails if .env.enc does not exist."""
    with pytest.raises(SystemExit) as exc:
        main(["run", "--env-file", str(tmp_path / "missing.enc"), "--", "echo", "1"])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_empty_password_fails(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies 'envshield run' fails if password entered is empty."""
    monkeypatch.delenv("ENVSHIELD_KEY", raising=False)
    enc_file = tmp_path / ".env.enc"
    enc_file.write_bytes(b"dummy")

    with mock.patch("getpass.getpass", return_value=""), pytest.raises(SystemExit) as exc:
        main(["run", "--env-file", str(enc_file), "--", "echo", "1"])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_wrong_key_fails(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies that 'envshield run' fails with non-zero exit when key is wrong."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    enc_file = tmp_path / ".env.enc"
    env_file.write_text("SECRET=1\n", encoding="utf-8")
    seal_file(env_file, enc_file, "correct_pass")

    monkeypatch.setenv("ENVSHIELD_KEY", "wrong_pass")
    with pytest.raises(SystemExit) as exc:
        main(["run", "--", sys.executable, "-c", "exit(0)"])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_no_command_fails(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies that 'envshield run' with no command fails."""
    monkeypatch.chdir(tmp_path)
    enc_file = tmp_path / ".env.enc"
    enc_file.write_bytes(b"dummy")

    with pytest.raises(SystemExit) as exc:
        main(["run"])
    assert exc.value.code == 1


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_scan_subcommand(mock_exit, tmp_path: Path, monkeypatch):
    """Verifies that 'envshield scan' dispatches to scanning logic."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dummy.txt").write_text("hello")

    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path)])
    assert exc.value.code == 0
