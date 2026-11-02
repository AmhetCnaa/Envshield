from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

from envshield.core.keychain import (
    SessionKeychain,
    cache_vault_key,
    clear_cached_vault_key,
    get_cached_vault_key,
    get_ssh_agent_identities,
    has_ssh_agent,
)


def test_key_id_computation(tmp_path: Path) -> None:
    f1 = tmp_path / "vault1.enc"
    f1.write_bytes(b"dummy")
    id1 = SessionKeychain.compute_key_id(f1)
    id2 = SessionKeychain.compute_key_id(str(f1))
    assert id1 == id2
    assert len(id1) == 16


def test_store_and_retrieve_secret() -> None:
    key_id = "test_store_01"
    secret = b"my_super_secret_session_token_32b!"
    try:
        ok = SessionKeychain.store_secret(key_id, secret, ttl_seconds=10)
        assert ok is True

        retrieved = SessionKeychain.retrieve_secret(key_id)
        assert retrieved is not None
        assert bytes(retrieved) == secret
        assert isinstance(retrieved, bytearray)
    finally:
        SessionKeychain.delete_secret(key_id)


def test_ttl_expiration() -> None:
    key_id = "test_ttl_02"
    secret = b"ephemeral_secret"
    SessionKeychain.delete_secret(key_id)
    try:
        SessionKeychain.store_secret(key_id, secret, ttl_seconds=1)
        # Should be valid immediately
        assert SessionKeychain.retrieve_secret(key_id) == secret

        # Sleep past TTL
        time.sleep(1.15)
        # Should be expired and automatically wiped
        assert SessionKeychain.retrieve_secret(key_id) is None
    finally:
        SessionKeychain.delete_secret(key_id)


def test_delete_and_clear_all() -> None:
    k1 = "test_del_k1"
    k2 = "test_del_k2"
    try:
        SessionKeychain.store_secret(k1, b"val1", ttl_seconds=30)
        SessionKeychain.store_secret(k2, b"val2", ttl_seconds=30)

        assert SessionKeychain.retrieve_secret(k1) == b"val1"
        assert SessionKeychain.delete_secret(k1) is True
        assert SessionKeychain.retrieve_secret(k1) is None
        assert SessionKeychain.delete_secret(k1) is False

        # Clear remaining
        count = SessionKeychain.clear_all()
        assert count >= 1
        assert SessionKeychain.retrieve_secret(k2) is None
    finally:
        SessionKeychain.delete_secret(k1)
        SessionKeychain.delete_secret(k2)


def test_vault_key_caching_helpers(tmp_path: Path) -> None:
    vault = tmp_path / "prod.env.enc"
    vault.write_bytes(b"encrypted_vault_data")
    secret_dek = bytearray(b"0123456789abcdef0123456789abcdef")

    try:
        assert cache_vault_key(vault, secret_dek, ttl_seconds=60) is True
        retrieved = get_cached_vault_key(vault)
        assert retrieved == secret_dek

        assert clear_cached_vault_key(vault) is True
        assert get_cached_vault_key(vault) is None
    finally:
        clear_cached_vault_key(vault)


def test_corrupted_session_file() -> None:
    from envshield.core.keychain import _get_cache_dir

    key_id = "test_corrupted_03"
    target = _get_cache_dir() / f"{key_id}.sess"
    target.write_bytes(b"garbage_non_dpapi_data")

    try:
        # Should safely handle corruption, delete file, and return None
        ret = SessionKeychain.retrieve_secret(key_id)
        assert ret is None
        assert not target.is_file()
    finally:
        target.unlink(missing_ok=True)


def test_ssh_agent_detection() -> None:
    # Test with mocked environment
    with patch.dict("os.environ", {"SSH_AUTH_SOCK": "/tmp/mock_agent.sock"}, clear=False):
        with patch("os.path.exists", return_value=True):
            assert has_ssh_agent() is True

    # Test get_ssh_agent_identities mock
    with patch("envshield.core.keychain.has_ssh_agent", return_value=True):
        mock_output = "256 SHA256:abc1234 user@host (ED25519)\n2048 SHA256:xyz5678 user@work (RSA)"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = mock_output
            identities = get_ssh_agent_identities()
            assert len(identities) == 2
            assert "SHA256:abc1234" in identities[0]
