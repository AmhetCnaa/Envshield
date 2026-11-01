from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from envshield.core.recipients import (
    Recipient,
    decrypt_dek_with_identity,
    encrypt_dek_for_recipient,
    find_default_identities,
)


def test_rsa_recipient_encrypt_decrypt(tmp_path):
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()

    pub_ssh = pub_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    recipient = Recipient.from_string(pub_ssh)
    assert recipient.key_type == "ssh-rsa"
    assert recipient.fingerprint

    dek = os.urandom(32)
    slot = encrypt_dek_for_recipient(dek, recipient)
    assert slot["type"] == "ssh-rsa"

    # Save private key to temp file
    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    priv_file = tmp_path / "id_rsa"
    priv_file.write_bytes(priv_pem)

    decrypted_dek = decrypt_dek_with_identity(slot, priv_file)
    assert decrypted_dek == dek

    # Decrypting with wrong key
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    wrong_file = tmp_path / "wrong_rsa"
    wrong_file.write_bytes(wrong_pem)

    assert decrypt_dek_with_identity(slot, wrong_file) is None


def test_ed25519_recipient_encrypt_decrypt(tmp_path):
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    pub_ssh = pub_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    recipient = Recipient.from_string(pub_ssh)
    assert recipient.key_type == "ssh-ed25519"

    dek = os.urandom(32)
    slot = encrypt_dek_for_recipient(dek, recipient)
    assert slot["type"] == "ssh-ed25519"
    assert "ephemeral_pub" in slot
    assert "nonce" in slot

    # Save private key to OpenSSH format
    priv_ssh = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    priv_file = tmp_path / "id_ed25519"
    priv_file.write_bytes(priv_ssh)

    decrypted_dek = decrypt_dek_with_identity(slot, priv_file)
    assert decrypted_dek == dek


def test_find_default_identities():
    ids = find_default_identities()
    assert isinstance(ids, list)
