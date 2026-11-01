from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P_25519: int = 2**255 - 19


def ed25519_pub_to_x25519_pub(ed_pub_bytes: bytes) -> bytes:
    """Converts Ed25519 public key bytes to X25519 Montgomery public key bytes."""
    y = int.from_bytes(ed_pub_bytes, "little") & ((1 << 255) - 1)
    u = ((1 + y) * pow(1 - y, P_25519 - 2, P_25519)) % P_25519
    return u.to_bytes(32, "little")


def ed25519_priv_to_x25519_priv(ed_priv_seed: bytes) -> bytes:
    """Converts Ed25519 private seed (32 bytes) to X25519 private key bytes."""
    h = hashlib.sha512(ed_priv_seed).digest()
    s = bytearray(h[:32])
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return bytes(s)


class Recipient:
    """Represents a public key recipient eligible to unlock a vault."""

    def __init__(self, key_type: str, public_key_obj: Any, fingerprint: str, raw_str: str) -> None:
        self.key_type = key_type  # "ssh-rsa" or "ssh-ed25519" or "x25519"
        self.public_key_obj = public_key_obj
        self.fingerprint = fingerprint
        self.raw_str = raw_str

    @classmethod
    def from_string(cls, text: str) -> Recipient:
        cleaned = text.strip()

        # Check if text is a file path
        possible_path = Path(cleaned).expanduser()
        if possible_path.is_file():
            cleaned = possible_path.read_text(encoding="utf-8").strip()

        # Handle OpenSSH public key line (e.g. ssh-ed25519 AAAAC... user@host)
        try:
            pub_key = serialization.load_ssh_public_key(cleaned.encode("utf-8"))
            fp = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]

            if isinstance(pub_key, rsa.RSAPublicKey):
                return cls("ssh-rsa", pub_key, fp, cleaned)
            if isinstance(pub_key, ed25519.Ed25519PublicKey):
                # Convert to X25519
                raw_ed = pub_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                x25519_bytes = ed25519_pub_to_x25519_pub(raw_ed)
                x_pub = x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
                return cls("ssh-ed25519", x_pub, fp, cleaned)
        except Exception:
            pass

        # Handle raw PEM or X25519 public key
        try:
            pub_key = serialization.load_pem_public_key(cleaned.encode("utf-8"))
            fp = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]
            if isinstance(pub_key, rsa.RSAPublicKey):
                return cls("ssh-rsa", pub_key, fp, cleaned)
            if isinstance(pub_key, x25519.X25519PublicKey):
                return cls("x25519", pub_key, fp, cleaned)
        except Exception:
            pass

        raise ValueError(f"Unsupported or invalid recipient public key format: '{text[:30]}...'")


def encrypt_dek_for_recipient(dek: bytes, recipient: Recipient) -> dict[str, str]:
    """
    Encrypts the 256-bit DEK for a given recipient and returns a slot dictionary.
    """
    if recipient.key_type == "ssh-rsa":
        # Use RSA-OAEP with SHA-256
        rsa_key: rsa.RSAPublicKey = recipient.public_key_obj
        enc_dek = rsa_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {
            "type": "ssh-rsa",
            "fingerprint": recipient.fingerprint,
            "encrypted_dek": base64.b64encode(enc_dek).decode("utf-8"),
        }

    if recipient.key_type in ("ssh-ed25519", "x25519"):
        # ECDH with ephemeral X25519 key pair + HKDF + AES-GCM
        recipient_x_pub: x25519.X25519PublicKey = recipient.public_key_obj
        ephem_priv = x25519.X25519PrivateKey.generate()
        ephem_pub_bytes = ephem_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        shared_secret = ephem_priv.exchange(recipient_x_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"envshield-v2-slot",
        ).derive(shared_secret)

        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        enc_dek = aesgcm.encrypt(nonce, dek, None)

        return {
            "type": recipient.key_type,
            "fingerprint": recipient.fingerprint,
            "ephemeral_pub": base64.b64encode(ephem_pub_bytes).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "encrypted_dek": base64.b64encode(enc_dek).decode("utf-8"),
        }

    raise ValueError(f"Unknown recipient key type: {recipient.key_type}")


def find_default_identities() -> list[Path]:
    """
    Finds standard user SSH private keys in ~/.ssh/ directory.
    """
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.is_dir():
        return []

    candidates = [
        ssh_dir / "id_ed25519",
        ssh_dir / "id_rsa",
        ssh_dir / "id_ecdsa",
    ]
    return [p for p in candidates if p.is_file()]


def decrypt_dek_with_identity(
    slot: dict[str, str], identity_path_or_str: str | Path, passphrase: str | None = None
) -> bytes | None:
    """
    Attempts to decrypt the DEK in slot using an SSH private key.
    Returns decrypted DEK bytes on success, None if key does not match or fails.
    """
    ident_path = Path(identity_path_or_str).expanduser()
    if ident_path.is_file():
        key_data = ident_path.read_bytes()
    else:
        key_data = str(identity_path_or_str).encode("utf-8")

    pass_bytes = passphrase.encode("utf-8") if passphrase else None

    # Load private key
    priv_key: Any = None
    try:
        priv_key = serialization.load_ssh_private_key(key_data, password=pass_bytes)
    except Exception:
        try:
            priv_key = serialization.load_pem_private_key(key_data, password=pass_bytes)
        except Exception:
            return None

    slot_type = slot.get("type")

    if slot_type == "ssh-rsa" and isinstance(priv_key, rsa.RSAPrivateKey):
        enc_dek = base64.b64decode(slot["encrypted_dek"])
        try:
            return priv_key.decrypt(
                enc_dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            return None

    if slot_type in ("ssh-ed25519", "x25519"):
        x_priv: x25519.X25519PrivateKey | None = None
        if isinstance(priv_key, ed25519.Ed25519PrivateKey):
            raw_seed = priv_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            x_priv = x25519.X25519PrivateKey.from_private_bytes(
                ed25519_priv_to_x25519_priv(raw_seed)
            )
        elif isinstance(priv_key, x25519.X25519PrivateKey):
            x_priv = priv_key

        if x_priv and "ephemeral_pub" in slot and "encrypted_dek" in slot:
            ephem_pub_bytes = base64.b64decode(slot["ephemeral_pub"])
            nonce = base64.b64decode(slot["nonce"])
            enc_dek = base64.b64decode(slot["encrypted_dek"])

            ephem_pub = x25519.X25519PublicKey.from_public_bytes(ephem_pub_bytes)
            shared_secret = x_priv.exchange(ephem_pub)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"envshield-v2-slot",
            ).derive(shared_secret)

            aesgcm = AESGCM(derived_key)
            try:
                return aesgcm.decrypt(nonce, enc_dek, None)
            except Exception:
                return None

    return None
