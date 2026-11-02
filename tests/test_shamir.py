from __future__ import annotations

import os
from pathlib import Path

import pytest

from envshield.core.shamir import recover_secret, split_secret
from envshield.core.vault import AuthError, seal_file, unseal_to_memory


def test_split_and_recover_3_of_5() -> None:
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, shares=5)
    assert len(shares) == 5

    # Any 3 shares should reconstruct
    recovered = recover_secret([shares[0], shares[2], shares[4]])
    assert bytes(recovered) == secret

    # Another 3-combination
    recovered2 = recover_secret([shares[1], shares[3], shares[4]])
    assert bytes(recovered2) == secret


def test_recover_with_excess_shares() -> None:
    secret = b"deterministic_secret_for_testing"
    shares = split_secret(secret, threshold=2, shares=4)
    # Provide 3 shares when 2 are needed
    recovered = recover_secret([shares[0], shares[1], shares[2]])
    assert bytes(recovered) == secret


def test_insufficient_shares_fails() -> None:
    secret = os.urandom(16)
    shares = split_secret(secret, threshold=3, shares=5)
    with pytest.raises(ValueError, match="Insufficient shares"):
        recover_secret([shares[0], shares[1]])


def test_duplicate_shares_fails() -> None:
    secret = os.urandom(16)
    shares = split_secret(secret, threshold=3, shares=5)
    with pytest.raises(ValueError, match="Duplicate share"):
        recover_secret([shares[0], shares[0], shares[1]])


def test_tampered_share_fails() -> None:
    secret = os.urandom(16)
    shares = split_secret(secret, threshold=2, shares=3)
    # Tamper with the hex data in share 0
    parts = shares[0].split("-")
    parts[5] = "00" * len(secret)
    tampered = "-".join(parts)
    with pytest.raises(ValueError, match="checksum verification failed"):
        recover_secret([tampered, shares[1]])


def test_inconsistent_thresholds_fails() -> None:
    s1 = split_secret(b"secret1", threshold=2, shares=3)
    s2 = split_secret(b"secret2", threshold=3, shares=4)
    with pytest.raises(ValueError, match="Conflicting thresholds"):
        recover_secret([s1[0], s2[1]])


def test_vault_quorum_integration(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("DB_HOST=pg.internal\nDB_PASS=super_prod_pass_1234\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    # Seal with 3-of-5 Shamir quorum
    shares = seal_file(env_file, vault_file, quorum=(3, 5))
    assert shares is not None
    assert len(shares) == 5

    # Unseal with 3 valid shares
    secrets = unseal_to_memory(vault_file, shares=[shares[0], shares[2], shares[3]])
    assert secrets["DB_HOST"] == "pg.internal"
    assert secrets["DB_PASS"] == "super_prod_pass_1234"

    # Unseal with insufficient shares (2 shares) should fail
    with pytest.raises((AuthError, ValueError)):
        unseal_to_memory(vault_file, shares=[shares[0], shares[1]])
