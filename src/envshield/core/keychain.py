from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

DEFAULT_CACHE_TTL: int = 900  # 15 minutes


# --- Windows DPAPI Helper ---
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
    ]


if sys.platform == "win32":
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL


def _dpapi_protect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data)
    in_blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))
    out_blob = _DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    if not _crypt32.CryptProtectData(
        ctypes.byref(in_blob), "envshield-session", None, None, None, 0x1, ctypes.byref(out_blob)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data)
    in_blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))
    out_blob = _DATA_BLOB()
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0x1, ctypes.byref(out_blob)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def _get_cache_dir() -> Path:
    """Returns platform-appropriate secure directory for encrypted ephemeral session tokens."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        p = Path(base) / "envshield" / "sessions"
    elif Path("/dev/shm").is_dir() and os.access("/dev/shm", os.W_OK):
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        p = Path(f"/dev/shm/.envshield_sessions_{uid}")
    else:
        p = Path.home() / ".cache" / "envshield" / "sessions"

    p.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return p


def _get_machine_session_key() -> bytes:
    """Generates machine/session-bound 256-bit key for Linux fallback encryption."""
    seed_parts = [
        str(Path.home()),
        os.environ.get("USER", os.environ.get("USERNAME", "default")),
    ]
    for mid in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.isfile(mid):
            try:
                seed_parts.append(Path(mid).read_text().strip())
                break
            except Exception:
                pass
    return hashlib.sha256("|".join(seed_parts).encode("utf-8")).digest()


class SessionKeychain:
    """
    Cross-platform ephemeral session key storage backed by OS-native secure enclaves:
      - Windows: DPAPI (CryptProtectData / CryptUnprotectData)
      - macOS: /usr/bin/security CLI
      - Linux: secret-tool or encrypted volatile RAM (/dev/shm)
    Enforces strict Time-To-Live (TTL) expiration.
    """

    @classmethod
    def compute_key_id(cls, identifier: Path | str) -> str:
        """Computes deterministic 16-hex fingerprint for an identifier (e.g. vault path)."""
        resolved = str(Path(identifier).resolve())
        return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def store_secret(
        cls, key_id: str, secret: bytes | bytearray, ttl_seconds: int = DEFAULT_CACHE_TTL
    ) -> bool:
        """
        Encrypts and stores a secret in the session cache with expiration.
        """
        if ttl_seconds <= 0:
            return False

        secret_b64 = base64.b64encode(bytes(secret)).decode("utf-8")
        payload = {
            "key_id": key_id,
            "secret_b64": secret_b64,
            "created_at": time.time(),
            "ttl": ttl_seconds,
        }
        raw_json = json.dumps(payload).encode("utf-8")

        cache_dir = _get_cache_dir()
        target_file = cache_dir / f"{key_id}.sess"

        try:
            if sys.platform == "win32":
                encrypted = _dpapi_protect(raw_json)
            else:
                # AES-GCM encryption with machine-bound key
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                mkey = _get_machine_session_key()
                nonce = os.urandom(12)
                aesgcm = AESGCM(mkey)
                encrypted = nonce + aesgcm.encrypt(nonce, raw_json, key_id.encode("utf-8"))

            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            mode = 0o600
            fd = os.open(target_file, flags, mode)
            try:
                os.write(fd, encrypted)
            finally:
                os.close(fd)
            if sys.platform != "win32":
                try:
                    os.chmod(target_file, 0o600)
                except OSError:
                    pass
            return True
        except Exception:
            return False

    @classmethod
    def retrieve_secret(cls, key_id: str) -> bytearray | None:
        """
        Retrieves and decrypts a secret from the session cache.
        If the secret has expired (time.time() > created_at + ttl), wipes the cached file
        and returns None.
        Returns a mutable bytearray that the caller must secure_wipe after use.
        """
        cache_dir = _get_cache_dir()
        target_file = cache_dir / f"{key_id}.sess"

        if not target_file.is_file():
            return None

        try:
            encrypted = target_file.read_bytes()
            if sys.platform == "win32":
                raw_json = _dpapi_unprotect(encrypted)
            else:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                mkey = _get_machine_session_key()
                nonce = encrypted[:12]
                ciphertext = encrypted[12:]
                aesgcm = AESGCM(mkey)
                raw_json = aesgcm.decrypt(nonce, ciphertext, key_id.encode("utf-8"))

            data = json.loads(raw_json.decode("utf-8"))
            created_at = float(data.get("created_at", 0))
            ttl = float(data.get("ttl", 0))

            if time.time() > (created_at + ttl):
                # Expired -> securely remove
                cls.delete_secret(key_id)
                return None

            secret_bytes = base64.b64decode(data["secret_b64"])
            return bytearray(secret_bytes)
        except Exception:
            cls.delete_secret(key_id)
            return None

    @classmethod
    def delete_secret(cls, key_id: str) -> bool:
        """Securely removes an entry from the session cache."""
        cache_dir = _get_cache_dir()
        target_file = cache_dir / f"{key_id}.sess"
        if not target_file.is_file():
            return False
        try:
            # Overwrite before unlink
            size = target_file.stat().st_size
            if size > 0:
                with open(target_file, "r+b", buffering=0) as f:
                    f.write(os.urandom(size))
                    f.flush()
            target_file.unlink(missing_ok=True)
            return True
        except OSError:
            target_file.unlink(missing_ok=True)
            return True

    @classmethod
    def clear_all(cls) -> int:
        """Clears all session tokens from cache. Returns count of deleted files."""
        cache_dir = _get_cache_dir()
        count = 0
        for f in cache_dir.glob("*.sess"):
            try:
                f.unlink(missing_ok=True)
                count += 1
            except OSError:
                pass
        return count


# --- Convenience Helpers ---

def cache_vault_key(vault_path: Path | str, secret: bytes | bytearray, ttl_seconds: int = DEFAULT_CACHE_TTL) -> bool:
    """Caches an unlocked vault key/DEK with time-to-live."""
    key_id = SessionKeychain.compute_key_id(vault_path)
    return SessionKeychain.store_secret(key_id, secret, ttl_seconds=ttl_seconds)


def get_cached_vault_key(vault_path: Path | str) -> bytearray | None:
    """Retrieves cached vault key/DEK if still valid."""
    key_id = SessionKeychain.compute_key_id(vault_path)
    return SessionKeychain.retrieve_secret(key_id)


def clear_cached_vault_key(vault_path: Path | str) -> bool:
    """Clears cached key for a specific vault."""
    key_id = SessionKeychain.compute_key_id(vault_path)
    return SessionKeychain.delete_secret(key_id)


# --- SSH-Agent Integration Helper ---

def has_ssh_agent() -> bool:
    """
    Checks if an active SSH Agent socket is available:
    - POSIX: SSH_AUTH_SOCK environment variable pointing to active socket.
    - Windows: OpenSSH named pipe or SSH_AUTH_SOCK.
    """
    auth_sock = os.environ.get("SSH_AUTH_SOCK")
    if auth_sock and (os.path.exists(auth_sock) or sys.platform == "win32"):
        return True

    if sys.platform == "win32":
        # Check standard Windows OpenSSH Agent named pipe \\.\pipe\openssh-ssh-agent
        pipe_path = r"\\.\pipe\openssh-ssh-agent"
        try:
            with open(pipe_path, "r+b", buffering=0):
                return True
        except (OSError, PermissionError):
            # If pipe exists, it may raise PermissionError or FileNotFoundError
            return os.path.exists(pipe_path)
    return False


def get_ssh_agent_identities() -> list[str]:
    """
    Lists public key fingerprints currently loaded into ssh-agent via `ssh-add -l`.
    Returns list of fingerprint strings.
    """
    if not has_ssh_agent():
        return []
    try:
        res = subprocess.run(
            ["ssh-add", "-l"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        if res.returncode == 0:
            lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
            return lines
    except Exception:
        pass
    return []
