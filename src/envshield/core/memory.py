from __future__ import annotations

import ctypes
import gc
import os
import sys
from types import TracebackType
from typing import Self


def _get_buffer_address(data: bytes | bytearray) -> int | None:
    """Extracts the raw virtual memory address of a bytearray or bytes buffer."""
    if isinstance(data, bytearray):
        return ctypes.addressof(ctypes.c_char.from_buffer(data))
    if isinstance(data, bytes):
        return ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p).value
    return None


def disable_core_dumps() -> bool:
    """
    Hardens the current process against memory dump leaks:
      - POSIX: sets RLIMIT_CORE to (0, 0) to prevent core dumps on crash/SIGSEGV.
      - Linux: invokes prctl(PR_SET_DUMPABLE, 0) to restrict ptrace attachment.
      - Windows: sets SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS to suppress WER dumps.
    """
    try:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            # SEM_FAILCRITICALERRORS (0x0001) | SEM_NOGPFAULTERRORBOX (0x0002)
            kernel32.SetErrorMode(0x0001 | 0x0002)
            return True

        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None)
            # PR_SET_DUMPABLE = 4
            libc.prctl(4, 0, 0, 0, 0)
        return True
    except Exception:
        return False


def lock_memory(data: bytes | bytearray) -> bool:
    """
    Attempts to lock the buffer in physical RAM to prevent OS swapping to disk/pagefile.
    Returns True if successfully locked, False otherwise (e.g. insufficient OS quota).
    """
    if not data:
        return True

    buf_len = len(data)
    try:
        addr = _get_buffer_address(data)
        if not addr:
            return False

        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualLock.restype = ctypes.c_bool
            return bool(kernel32.VirtualLock(addr, buf_len))

        libc = ctypes.CDLL(None)
        if hasattr(libc, "mlock"):
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype = ctypes.c_int
            res = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(buf_len))
            return res == 0
    except Exception:
        return False

    return False


def unlock_memory(data: bytes | bytearray) -> bool:
    """
    Unlocks previously locked physical RAM pages.
    """
    if not data:
        return True

    buf_len = len(data)
    try:
        addr = _get_buffer_address(data)
        if not addr:
            return False

        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualUnlock.restype = ctypes.c_bool
            return bool(kernel32.VirtualUnlock(addr, buf_len))

        libc = ctypes.CDLL(None)
        if hasattr(libc, "munlock"):
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock.restype = ctypes.c_int
            res = libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(buf_len))
            return res == 0
    except Exception:
        return False

    return False


def secure_wipe(buffer: bytearray | memoryview) -> None:
    """
    Cryptographically overwrites a mutable memory buffer in-place with zeroes.
    """
    if not buffer:
        return

    buf_len = len(buffer)
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        ctypes.memset(addr, 0, buf_len)
    except Exception:
        for i in range(buf_len):
            buffer[i] = 0


class SecureBuffer:
    """
    A protected mutable memory buffer that locks pages in physical RAM (VirtualLock / mlock),
    disables crash core dumps, and deterministically zeroes memory via ctypes.memset on exit.
    """

    def __init__(self, data: bytes | bytearray | str) -> None:
        disable_core_dumps()
        if isinstance(data, str):
            raw = data.encode("utf-8")
        else:
            raw = bytes(data)

        self._buf = bytearray(raw)
        self._locked = lock_memory(self._buf)

    @property
    def buffer(self) -> bytearray:
        return self._buf

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def to_str(self) -> str:
        return self._buf.decode("utf-8")

    def wipe(self) -> None:
        if self._locked:
            unlock_memory(self._buf)
            self._locked = False
        secure_wipe(self._buf)
        gc.collect()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe()


class ObfuscatedSecretStore:
    """
    Stores key-value secrets in RAM masked with an ephemeral per-instance CSPRNG XOR pad
    inside locked bytearray buffers. Prevents raw cleartext strings from lingering in the
    heap while the parent supervisor waits for child processes to finish.
    """

    def __init__(self, secrets: dict[str, str]) -> None:
        disable_core_dumps()
        self._entries: dict[str, tuple[SecureBuffer, SecureBuffer]] = {}
        for k, v in secrets.items():
            raw_bytes = v.encode("utf-8")
            pad = os.urandom(len(raw_bytes))
            masked = bytearray(b ^ p for b, p in zip(raw_bytes, pad, strict=True))
            self._entries[k] = (SecureBuffer(masked), SecureBuffer(pad))

    def reveal(self, key: str) -> str | None:
        """Unmasks a single secret on-demand."""
        pair = self._entries.get(key)
        if not pair:
            return None
        masked_buf, pad_buf = pair
        unmasked = bytearray(
            b ^ p for b, p in zip(masked_buf.buffer, pad_buf.buffer, strict=True)
        )
        try:
            return unmasked.decode("utf-8")
        finally:
            secure_wipe(unmasked)

    def reveal_all(self) -> dict[str, str]:
        """Materializes the dictionary when passing to subprocess environment."""
        return {k: (self.reveal(k) or "") for k in self._entries}

    def wipe_all(self) -> None:
        """Zeroes both the masked payloads and the one-time pads in physical RAM."""
        for masked_buf, pad_buf in self._entries.values():
            masked_buf.wipe()
            pad_buf.wipe()
        self._entries.clear()
        gc.collect()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe_all()
