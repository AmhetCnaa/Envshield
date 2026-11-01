from __future__ import annotations

import ctypes
import os
import sys
from types import TracebackType
from typing import Self


def lock_memory(data: bytes | bytearray) -> bool:
    """
    Attempts to lock the buffer in physical RAM to prevent OS swapping to disk/pagefile.
    Returns True if successfully locked, False otherwise (e.g. insufficient privileges).
    """
    if not data:
        return True

    buf_len = len(data)
    try:
        if isinstance(data, bytearray):
            addr = ctypes.addressof(ctypes.c_char.from_buffer(data))
        else:
            addr = ctypes.c_void_p.from_buffer(data).value
            if not addr:
                return False

        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualLock.restype = ctypes.c_bool
            return bool(kernel32.VirtualLock(addr, buf_len))

        if hasattr(os, "mlock"):
            # If standard library or libc has mlock
            libc = ctypes.CDLL(None)
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
        if isinstance(data, bytearray):
            addr = ctypes.addressof(ctypes.c_char.from_buffer(data))
        else:
            addr = ctypes.c_void_p.from_buffer(data).value
            if not addr:
                return False

        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualUnlock.restype = ctypes.c_bool
            return bool(kernel32.VirtualUnlock(addr, buf_len))

        if hasattr(os, "munlock"):
            libc = ctypes.CDLL(None)
            res = libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(buf_len))
            return res == 0
    except Exception:
        return False

    return False


def secure_wipe(buffer: bytearray | memoryview) -> None:
    """
    Cryptographically overwrites the mutable memory buffer in-place with zeroes.
    """
    if not buffer:
        return

    buf_len = len(buffer)
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        ctypes.memset(addr, 0, buf_len)
    except Exception:
        # Fallback to manual byte overwrite
        for i in range(buf_len):
            buffer[i] = 0


class SecureBuffer:
    """
    A protected memory buffer that attempts to lock pages in RAM
    and automatically zeroes memory when exited.
    """

    def __init__(self, data: bytes | bytearray | str) -> None:
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

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe()
