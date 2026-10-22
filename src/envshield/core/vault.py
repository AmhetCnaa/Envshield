from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE: int = 16
NONCE_SIZE: int = 12
KEY_SIZE: int = 32
PBKDF2_ITERATIONS: int = 100_000


class AuthError(Exception):
    """Base exception for authentication or decryption failures."""


class InvalidKey(AuthError):
    """Raised when an invalid key or password is provided."""


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


def parse_env_content(content: str) -> dict[str, str]:
    """
    Parses .env file content strictly in memory without writing to disk.
    Supports comments (#), empty lines, optional 'export ', and quoted values.
    """
    env_vars: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            # Strip matching surrounding quotes
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            env_vars[key] = val
    return env_vars


def seal_file(source_path: Path | str, target_path: Path | str, password: str) -> None:
    """
    Reads source_path, encrypts its content using AES-256-GCM with a key derived from password,
    and writes [salt (16B) + nonce (12B) + ciphertext] directly to target_path.
    """
    source = Path(source_path)
    target = Path(target_path)

    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")

    plaintext = source.read_bytes()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    payload = salt + nonce + ciphertext
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def _decrypt_payload(payload: bytes, password: str) -> bytes:
    """
    Internal helper to decrypt [salt (16B) + nonce (12B) + ciphertext] using AES-GCM.
    """
    min_length = SALT_SIZE + NONCE_SIZE + 16  # 16-byte GCM authentication tag
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


def unseal_to_memory(source_path: Path | str, password: str) -> dict[str, str]:
    """
    Reads an encrypted environment file (.env.enc), decrypts it in RAM using AES-GCM,
    and parses it into a dictionary of KEY=VALUE pairs.
    Zero-disk writes: plaintext is never written to disk.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source}")

    raw_bytes = source.read_bytes()
    decrypted_bytes: bytes

    try:
        decrypted_bytes = _decrypt_payload(raw_bytes, password)
    except (InvalidKey, AuthError) as original_err:
        # Fallback support for base64 encoded payload
        try:
            candidate = base64.b64decode(raw_bytes, validate=True)
            decrypted_bytes = _decrypt_payload(candidate, password)
        except (binascii.Error, ValueError, AuthError):
            raise original_err from None

    try:
        content = decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthError("Decrypted payload is not valid UTF-8 text.") from exc

    return parse_env_content(content)


def shred_file(path: Path | str, passes: int = 3) -> None:
    """
    Securely overwrites and removes a file to prevent recovery from disk.
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
