from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envshield.core.k8s_bridge import apply_k8s_secret, build_k8s_secret_manifest
from envshield.core.recipients import (
    KeyExpiredError,
    Recipient,
    decrypt_dek_with_identity,
    encrypt_dek_for_recipient,
)
from envshield.core.vault import InvalidKey, seal_file, unseal_to_memory


def test_build_k8s_secret_manifest() -> None:
    secrets = {"API_KEY": "secret123", "PORT": "8080"}
    manifest = build_k8s_secret_manifest(
        secret_name="backend-secrets",
        secrets=secrets,
        namespace="production",
        labels={"tier": "backend"},
        annotations={"reloader.stakater.com/auto": "true"},
    )
    assert manifest["apiVersion"] == "v1"
    assert manifest["kind"] == "Secret"
    assert manifest["metadata"]["name"] == "backend-secrets"
    assert manifest["metadata"]["namespace"] == "production"
    assert manifest["metadata"]["labels"]["tier"] == "backend"
    assert manifest["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "envshield"
    assert manifest["metadata"]["annotations"]["reloader.stakater.com/auto"] == "true"
    assert manifest["stringData"]["API_KEY"] == "secret123"


def test_apply_k8s_secret_via_stdin_pipe() -> None:
    secrets = {"TOP_SECRET_TOKEN": "classified_123"}
    with patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("secret/backend-secrets configured\n", "")
        mock_popen.return_value = mock_proc

        exit_code, msg = apply_k8s_secret(
            secret_name="backend-secrets",
            secrets=secrets,
            namespace="default",
            dry_run=True,
        )
        assert exit_code == 0
        assert "secret/backend-secrets configured" in msg

        # Invariant checks:
        # 1. shell=False must be strictly enforced
        cmd_args, kwargs = mock_popen.call_args
        assert kwargs.get("shell") is False
        assert kwargs.get("stdin") is not None

        # 2. Secret value MUST NOT appear anywhere in the argv command line
        cmd = cmd_args[0]
        assert "classified_123" not in " ".join(cmd)
        assert cmd[:4] == ["kubectl", "apply", "-f", "-"]

        # 3. Manifest payload sent via communicate() input
        comm_input = mock_proc.communicate.call_args[1]["input"]
        payload_data = json.loads(comm_input)
        assert payload_data["stringData"]["TOP_SECRET_TOKEN"] == "classified_123"


def test_vault_with_future_ttl_unseals(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SERVICE_KEY=valid_future_key\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    future_exp = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seal_file(env_file, vault_file, password="test_password", expires_at=future_exp)

    # Should unseal successfully because expiry is in the future
    secrets = unseal_to_memory(vault_file, password="test_password")
    assert secrets["SERVICE_KEY"] == "valid_future_key"


def test_vault_with_past_ttl_fails_cryptographically(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SERVICE_KEY=expired_key\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    past_exp = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seal_file(env_file, vault_file, password="test_password", expires_at=past_exp)

    # Unseal should reject the expired slot/vault with KeyExpiredError
    with pytest.raises(KeyExpiredError, match="expired"):
        unseal_to_memory(vault_file, password="test_password")


def test_tampered_expires_at_violates_aad(tmp_path: Path) -> None:
    """
    Verifies that an attacker cannot extend an expired vault by manually editing the
    "expires_at" string in the JSON header. The AES-256-GCM payload AAD or slot AAD
    will fail to authenticate and raise InvalidKey.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("SUPER_SECRET=vault_payload\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    past_exp = "2020-01-01T00:00:00Z"
    seal_file(env_file, vault_file, password="my_password", expires_at=past_exp)

    raw_vault = vault_file.read_bytes()
    # Replace 2020 with 2099 in the header
    tampered_bytes = re.sub(b"2020-01-01T00:00:00Z", b"2099-01-01T00:00:00Z", raw_vault)
    vault_file.write_bytes(tampered_bytes)

    # Decryption should fail due to AAD / GCM tag mismatch
    with pytest.raises(InvalidKey, match="Authentication failed"):
        unseal_to_memory(vault_file, password="my_password")


def test_recipient_slot_with_cryptographic_ttl() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # Generate an ephemeral Ed25519 keypair
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_ssh = pub.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    rec = Recipient.from_string(pub_ssh)
    dek = b"thirty_two_byte_dek_test_key!!!!"

    # Future expiry: encrypt and decrypt
    future_exp = (datetime.now(timezone.utc) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    slot = encrypt_dek_for_recipient(dek, rec, expires_at=future_exp)
    assert slot.get("expires_at") == future_exp

    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    decrypted = decrypt_dek_with_identity(slot, priv_pem)
    assert decrypted == dek

    # Past expiry: should raise KeyExpiredError
    past_exp = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    slot_expired = encrypt_dek_for_recipient(dek, rec, expires_at=past_exp)
    with pytest.raises(KeyExpiredError, match="expired"):
        decrypt_dek_with_identity(slot_expired, priv_pem)
