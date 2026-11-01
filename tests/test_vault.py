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
    assert "[REDACTED:TEST_KEY]" in out

    exit_code_raw = execute_with_env(command, secrets, redact=False)
    assert exit_code_raw == 0
    out_raw, _ = capfd.readouterr()
    assert "CONFIDENTIAL_INJECTED_VALUE_42" in out_raw


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
    with (
        mock.patch("getpass.getpass", return_value="test_password"),
        pytest.raises(SystemExit) as exc_seal,
    ):
        main(["seal"])
    assert exc_seal.value.code == 0

    enc_file = tmp_path / ".env.enc"
    assert enc_file.is_file()

    # 2. Test CLI run with ENVSHIELD_KEY environment variable
    monkeypatch.setenv("ENVSHIELD_KEY", "test_password")
    with pytest.raises(SystemExit) as exc_run:
        main(
            [
                "run",
                "--",
                sys.executable,
                "-c",
                "import os; print(os.environ['APP_TOKEN'])",
            ]
        )
    assert exc_run.value.code == 0

    out, _ = capfd.readouterr()
    assert "[REDACTED:APP_TOKEN]" in out


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_run_without_double_dash(mock_exit, tmp_path: Path, monkeypatch, capfd):
    """Verifies 'envshield run' without explicit '--' separator."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("DIRECT_VAR=direct_ok\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "direct_pass")

    monkeypatch.setenv("ENVSHIELD_KEY", "direct_pass")
    with pytest.raises(SystemExit) as exc_run:
        main(
            [
                "run",
                sys.executable,
                "-c",
                "import os; print(os.environ['DIRECT_VAR'])",
            ]
        )
    assert exc_run.value.code == 0

    out, _ = capfd.readouterr()
    assert "[REDACTED:DIRECT_VAR]" in out


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


def test_legacy_v1_vault_backwards_compatibility(tmp_path: Path):
    """Verifies that legacy v1 format (salt + nonce + ct) continues to unseal seamlessly."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from envshield.core.vault import derive_key, unseal_to_memory

    salt = b"1234567890123456"
    nonce = b"123456789012"
    key = derive_key("v1password", salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, b"V1_LEGACY_KEY=legacy_val\n", None)

    v1_file = tmp_path / "legacy.env.enc"
    v1_file.write_bytes(salt + nonce + ct)

    secrets = unseal_to_memory(v1_file, "v1password")
    assert secrets["V1_LEGACY_KEY"] == "legacy_val"


def test_team_ssh_recipient_vault(tmp_path: Path):
    """Verifies sealing for multiple SSH recipients and unsealing with each private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    # 1. Generate team keys
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_ssh = (
        rsa_priv.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("utf-8")
    )
    rsa_priv_file = tmp_path / "team_member1_rsa"
    rsa_priv_file.write_bytes(
        rsa_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub_ssh = (
        ed_priv.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("utf-8")
    )
    ed_priv_file = tmp_path / "team_member2_ed25519"
    ed_priv_file.write_bytes(
        ed_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
    )

    env_file = tmp_path / "team.env"
    env_file.write_text("TEAM_SECRET=all_hands_deck\n", encoding="utf-8")
    enc_file = tmp_path / "team.env.enc"

    # 2. Seal with both recipients, no password
    seal_file(env_file, enc_file, recipients=[rsa_pub_ssh, ed_pub_ssh])

    # 3. Unseal with member 1 (RSA)
    secrets1 = unseal_to_memory(enc_file, identity_path=rsa_priv_file)
    assert secrets1["TEAM_SECRET"] == "all_hands_deck"

    # 4. Unseal with member 2 (Ed25519)
    secrets2 = unseal_to_memory(enc_file, identity_path=ed_priv_file)
    assert secrets2["TEAM_SECRET"] == "all_hands_deck"


def test_hybrid_vault_password_and_recipients(tmp_path: Path):
    """Verifies a vault with both password and recipient slots can be unlocked by either."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub_ssh = (
        ed_priv.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("utf-8")
    )
    ed_priv_file = tmp_path / "member_ed"
    ed_priv_file.write_bytes(
        ed_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
    )

    env_file = tmp_path / "hybrid.env"
    env_file.write_text("HYBRID_KEY=multi_auth\n", encoding="utf-8")
    enc_file = tmp_path / "hybrid.env.enc"

    seal_file(env_file, enc_file, password="master_pass", recipients=[ed_pub_ssh])

    # Unlock via password
    assert unseal_to_memory(enc_file, password="master_pass")["HYBRID_KEY"] == "multi_auth"

    # Unlock via recipient private key (without password)
    assert unseal_to_memory(enc_file, identity_path=ed_priv_file)["HYBRID_KEY"] == "multi_auth"


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_key_commands(mock_exit, tmp_path: Path):
    """Tests 'envshield key set', 'envshield key get', and 'envshield key delete' CLI commands."""
    mock_store = {}

    with (
        mock.patch("keyring.set_password", side_effect=lambda s, n, v: mock_store.update({n: v})),
        mock.patch("keyring.get_password", side_effect=lambda s, n: mock_store.get(n)),
        mock.patch("keyring.delete_password", side_effect=lambda s, n: mock_store.pop(n, None)),
    ):
        with (
            mock.patch("getpass.getpass", return_value="mysecretpass"),
            pytest.raises(SystemExit) as e1,
        ):
            main(["key", "set", "prod_key"])
        assert e1.value.code == 0

        with pytest.raises(SystemExit) as e2:
            main(["key", "get", "prod_key"])
        assert e2.value.code == 0

        with pytest.raises(SystemExit) as e3:
            main(["key", "delete", "prod_key"])
        assert e3.value.code == 0


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_diff_command(mock_exit, tmp_path: Path, monkeypatch):
    """Tests 'envshield diff' CLI command."""
    monkeypatch.chdir(tmp_path)
    file_a = tmp_path / ".env"
    file_a.write_text("A=1\nB=2\n", encoding="utf-8")
    enc_file = tmp_path / ".env.enc"
    seal_file(file_a, enc_file, password="diff_pass")

    # Change unencrypted file
    file_a.write_text("A=1\nB=999\n", encoding="utf-8")

    monkeypatch.setenv("ENVSHIELD_KEY", "diff_pass")
    with pytest.raises(SystemExit) as e:
        main(["diff", str(file_a), str(enc_file)])
    assert e.value.code == 0
