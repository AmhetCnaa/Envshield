from __future__ import annotations

import base64
import binascii
import json
import os
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from envshield.core.audit import compute_key_fingerprint, record_audit_event
from envshield.core.formats import detect_format
from envshield.core.interpolator import interpolate_secrets
from envshield.core.memory import SecureBuffer, secure_wipe
from envshield.core.profiles import parse_secrets_with_profile
from envshield.core.recipients import (
    Recipient,
    decrypt_dek_with_identity,
    encrypt_dek_for_recipient,
    find_default_identities,
)

V2_MAGIC: bytes = b"ENVS\x02"
SALT_SIZE: int = 16
NONCE_SIZE: int = 12
KEY_SIZE: int = 32
PBKDF2_ITERATIONS: int = 100_000


class AuthError(Exception):
    """Base exception for authentication or decryption failures."""


class InvalidKey(AuthError):
    """Raised when an invalid key, private key, or password is provided."""


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES key from a password and salt using PBKDF2HMAC.
    Algorithm: SHA-256, 100,000 iterations.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def shred_file(path: Path | str, passes: int = 3) -> None:
    """
    Securely overwrites and removes a file to prevent forensic recovery.
    Overwrites with random bytes in multiple passes followed by zeros before deletion.
    """
    target = Path(path)
    if not target.is_file():
        return

    size = target.stat().st_size
    if size > 0:
        with open(target, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())

    target.unlink()


def seal_file(
    source_path: Path | str,
    target_path: Path | str,
    password: str | None = None,
    recipients: Sequence[str | Recipient] | None = None,
    format_type: str = "auto",
) -> None:
    """
    Encrypts source_path into target_path using AES-256-GCM envelope encryption.
    Supports single password, team SSH recipients, or hybrid (both).
    """
    source = Path(source_path)
    target = Path(target_path)

    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")

    if not password and not recipients:
        raise ValueError("At least one password or recipient public key must be provided.")

    plaintext = source.read_bytes()
    dek = bytearray(os.urandom(KEY_SIZE))
    payload_nonce = os.urandom(NONCE_SIZE)

    # Encrypt the plaintext payload with DEK using AES-256-GCM
    aesgcm = AESGCM(bytes(dek))
    ciphertext = aesgcm.encrypt(payload_nonce, plaintext, None)

    slots: list[dict[str, Any]] = []
    salt: bytes | None = None

    # 1. Password slot (if password provided)
    if password:
        salt = os.urandom(SALT_SIZE)
        slot_nonce = os.urandom(NONCE_SIZE)
        kek = derive_key(password, salt)
        slot_aesgcm = AESGCM(kek)
        encrypted_dek = slot_aesgcm.encrypt(slot_nonce, bytes(dek), None)

        slots.append(
            {
                "type": "password",
                "salt": base64.b64encode(salt).decode("utf-8"),
                "nonce": base64.b64encode(slot_nonce).decode("utf-8"),
                "encrypted_dek": base64.b64encode(encrypted_dek).decode("utf-8"),
                "iterations": PBKDF2_ITERATIONS,
            }
        )

    # 2. Recipient slots (if recipients provided)
    if recipients:
        for r_spec in recipients:
            recipient = (
                r_spec if isinstance(r_spec, Recipient) else Recipient.from_string(str(r_spec))
            )
            slot_info = encrypt_dek_for_recipient(bytes(dek), recipient)
            slots.append(slot_info)

    # Wipe DEK from memory after sealing
    secure_wipe(dek)

    detected_fmt = detect_format(source) if format_type == "auto" else format_type
    header_data = {
        "version": 2,
        "format": detected_fmt,
        "slots": slots,
        "payload_nonce": base64.b64encode(payload_nonce).decode("utf-8"),
    }
    header_bytes = json.dumps(header_data, separators=(",", ":")).encode("utf-8")

    # Layout: [V2_MAGIC (6B)] + [header_len (4B)] + [header_bytes] + [ciphertext + tag]
    payload = V2_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)

    record_audit_event(
        action="SEAL",
        target_path=target,
        key_id=compute_key_fingerprint(salt or (str(recipients[0]) if recipients else "vault")),
        details={"format": detected_fmt, "slots": len(slots)},
    )


def _decrypt_v1_payload(payload: bytes, password: str) -> bytes:
    """Decrypts legacy v1 format: [salt(16B) + nonce(12B) + ciphertext + tag]."""
    min_length = SALT_SIZE + NONCE_SIZE + 16
    if len(payload) < min_length:
        raise AuthError(f"Invalid payload: data too short (minimum {min_length} bytes required).")

    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = payload[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise InvalidKey("Authentication failed: invalid password or corrupted data.") from exc


def unseal_raw_payload(
    source_path: Path | str,
    password: str | None = None,
    identity_path: str | Path | None = None,
) -> tuple[str, str]:
    """
    Decrypts the encrypted vault in RAM.
    Returns a tuple of (plaintext_content, detected_format).
    Plaintext is kept in memory and never written to disk.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source}")

    raw_bytes = source.read_bytes()

    # Base64 envelope fallback check
    if not raw_bytes.startswith(V2_MAGIC) and len(raw_bytes) > 28:
        try:
            candidate = base64.b64decode(raw_bytes, validate=True)
            if candidate.startswith(V2_MAGIC) or len(candidate) >= 44:
                raw_bytes = candidate
        except (binascii.Error, ValueError):
            pass

    # Check for V2 Envelope format
    if raw_bytes.startswith(V2_MAGIC):
        if len(raw_bytes) < len(V2_MAGIC) + 4:
            raise AuthError("Invalid V2 vault: truncated header length.")

        header_len = struct.unpack(">I", raw_bytes[len(V2_MAGIC) : len(V2_MAGIC) + 4])[0]
        header_start = len(V2_MAGIC) + 4
        header_end = header_start + header_len

        if len(raw_bytes) < header_end + 16:
            raise AuthError("Invalid V2 vault: corrupted header or missing ciphertext.")

        try:
            header_json = json.loads(raw_bytes[header_start:header_end].decode("utf-8"))
        except Exception as exc:
            raise AuthError(f"Invalid V2 vault header: {exc}") from exc

        ciphertext = raw_bytes[header_end:]
        payload_nonce = base64.b64decode(header_json["payload_nonce"])
        slots: list[dict[str, Any]] = header_json.get("slots", [])
        fmt = header_json.get("format", "env")

        dek: bytearray | None = None

        # 1. Try specified identity private key
        if identity_path:
            for slot in slots:
                if slot.get("type") in ("ssh-rsa", "ssh-ed25519", "x25519"):
                    decrypted_dek = decrypt_dek_with_identity(slot, identity_path)
                    if decrypted_dek:
                        dek = bytearray(decrypted_dek)
                        break

        # 2. Try default SSH identities in ~/.ssh/
        if dek is None and not identity_path:
            default_ids = find_default_identities()
            for ident in default_ids:
                for slot in slots:
                    if slot.get("type") in ("ssh-rsa", "ssh-ed25519", "x25519"):
                        decrypted_dek = decrypt_dek_with_identity(slot, ident)
                        if decrypted_dek:
                            dek = bytearray(decrypted_dek)
                            break
                if dek is not None:
                    break

        # 3. Try password slot if available and password provided
        if dek is None and password:
            for slot in slots:
                if slot.get("type") == "password":
                    salt = base64.b64decode(slot["salt"])
                    slot_nonce = base64.b64decode(slot["nonce"])
                    enc_dek = base64.b64decode(slot["encrypted_dek"])
                    kek = derive_key(password, salt)
                    slot_aesgcm = AESGCM(kek)
                    try:
                        decrypted_dek = slot_aesgcm.decrypt(slot_nonce, enc_dek, None)
                        dek = bytearray(decrypted_dek)
                        break
                    except InvalidTag:
                        continue

        if dek is None:
            raise InvalidKey(
                "Authentication failed: no matching private key or valid password for this vault."
            )

        with SecureBuffer(bytes(dek)) as sec_dek:
            aesgcm = AESGCM(sec_dek.to_bytes())
            try:
                decrypted_bytes = aesgcm.decrypt(payload_nonce, ciphertext, None)
            except InvalidTag as exc:
                raise InvalidKey("Authentication failed: payload tag mismatch.") from exc

        try:
            plaintext = decrypted_bytes.decode("utf-8")
            record_audit_event(
                action="UNSEAL",
                target_path=source,
                key_id=compute_key_fingerprint(
                    password or (str(identity_path) if identity_path else "ssh_identity")
                ),
                details={"format": fmt, "version": 2},
            )
            return plaintext, fmt
        except UnicodeDecodeError as exc:
            raise AuthError("Decrypted payload is not valid UTF-8 text.") from exc

    # Legacy V1 format fallback
    if not password:
        raise InvalidKey("Password required to unseal legacy v1 vault.")

    try:
        decrypted_bytes = _decrypt_v1_payload(raw_bytes, password)
    except (InvalidKey, AuthError) as original_err:
        raise original_err from None

    try:
        plaintext = decrypted_bytes.decode("utf-8")
        record_audit_event(
            action="UNSEAL",
            target_path=source,
            key_id=compute_key_fingerprint(password or "legacy"),
            details={"format": "env", "version": 1},
        )
        return plaintext, "env"
    except UnicodeDecodeError as exc:
        raise AuthError("Decrypted payload is not valid UTF-8 text.") from exc


def unseal_to_memory(
    source_path: Path | str,
    password: str | None = None,
    identity_path: str | Path | None = None,
    profile: str | None = None,
    interpolate: bool = True,
) -> dict[str, str]:
    """
    Reads an encrypted environment file (.env.enc), decrypts it in RAM,
    resolves requested profile (if any), and recursively interpolates variables (${VAR}).
    Zero-disk writes: plaintext is never written to disk.
    """
    content, fmt = unseal_raw_payload(source_path, password, identity_path)
    secrets = parse_secrets_with_profile(
        content,
        profile=profile,
        format_type=fmt,
        path_hint=str(source_path),
    )
    if interpolate:
        secrets = interpolate_secrets(secrets)
    return secrets
