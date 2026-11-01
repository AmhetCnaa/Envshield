from __future__ import annotations

import ctypes
import gc
import os
import sys
from types import TracebackType
from typing import Self

_CORE_DUMPS_DISABLED: bool = False


def _get_buffer_address(data: bytes | bytearray) -> int | None:
    """Extracts the raw virtual memory address of a bytearray or bytes buffer."""
    if isinstance(data, bytearray):
        return ctypes.addressof(ctypes.c_char.from_buffer(data))
    if isinstance(data, bytes):
        return ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p).value
    return None


def disable_core_dumps(strict_ptrace: bool = False) -> bool:
    """
    Hardens the current process against memory dump leaks (singleton execution per process):
      - POSIX: sets RLIMIT_CORE to (0, 0) to prevent core dumps on crash/SIGSEGV.
      - Linux: optionally invokes prctl(PR_SET_DUMPABLE, 0) when `strict_ptrace=True` or
        `ENVSHIELD_STRICT_PTRACE=1` (kept opt-in so rootless containers and /proc/self/fd
        PTY operations do not suffer root:root ownership side effects).
      - Windows: sets SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS to suppress WER dumps.
    """
    global _CORE_DUMPS_DISABLED
    if _CORE_DUMPS_DISABLED:
        return True

    try:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            # SEM_FAILCRITICALERRORS (0x0001) | SEM_NOGPFAULTERRORBOX (0x0002)
            kernel32.SetErrorMode(0x0001 | 0x0002)
            _CORE_DUMPS_DISABLED = True
            return True

        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform.startswith("linux") and (
            strict_ptrace or os.environ.get("ENVSHIELD_STRICT_PTRACE") == "1"
        ):
            libc = ctypes.CDLL(None)
            # PR_SET_DUMPABLE = 4
            libc.prctl(4, 0, 0, 0, 0)
        _CORE_DUMPS_DISABLED = True
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
            self._buf = bytearray(data, "utf-8")
        elif isinstance(data, bytearray):
            # Copy directly from mutable bytearray without creating an intermediate immutable `bytes` object
            self._buf = bytearray(data)
            secure_wipe(data)
        else:
            self._buf = bytearray(data)

        self._locked = lock_memory(self._buf)

    @property
    def buffer(self) -> bytearray:
        return self._buf

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    def to_str(self) -> str:
        return self._buf.decode("utf-8")

    def wipe(self, unlock_page: bool = False) -> None:
        """
        Zeroes the underlying bytearray via ctypes.memset FIRST while the page is still
        locked in physical RAM.
        Note on OS Page Granularity: Because VirtualUnlock / munlock operate on 4 KB pages
        and Python's pymalloc co-locates small bytearray objects on shared pages, calling
        munlock on one buffer prematurely unlocks sibling buffers on the same 4 KB page.
        Therefore `unlock_page` defaults to False until full store teardown.
        """
        secure_wipe(self._buf)
        if self._locked and unlock_page:
            unlock_memory(self._buf)
            self._locked = False
        gc.collect()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe(unlock_page=True)


class ObfuscatedSecretStore:
    """
    Stores key-value secrets in RAM masked with an ephemeral per-instance CSPRNG XOR pad
    inside locked bytearray buffers. Prevents raw cleartext strings from lingering in the
    heap while the parent supervisor waits for child processes to finish.
    """

    def __init__(self, secrets: dict[str, str], clear_source: bool = False) -> None:
        disable_core_dumps()
        self._entries: dict[str, tuple[SecureBuffer, SecureBuffer]] = {}
        for k, v in secrets.items():
            raw_buf = bytearray(v, "utf-8")
            pad_buf = bytearray(os.urandom(len(raw_buf)))
            masked_buf = bytearray(b ^ p for b, p in zip(raw_buf, pad_buf, strict=True))
            secure_wipe(raw_buf)
            self._entries[k] = (SecureBuffer(masked_buf), SecureBuffer(pad_buf))

        if clear_source:
            secrets.clear()

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
        """
        Two-phase teardown to respect 4 KB OS page granularity:
          Phase 1: Cryptographically zero-wipe all buffers while all shared 4 KB pages remain locked.
          Phase 2: Unlock the physical RAM pages after every secret on those pages has been zeroed.
        """
        for masked_buf, pad_buf in self._entries.values():
            masked_buf.wipe(unlock_page=False)
            pad_buf.wipe(unlock_page=False)
        for masked_buf, pad_buf in self._entries.values():
            if masked_buf._locked:
                unlock_memory(masked_buf.buffer)
                masked_buf._locked = False
            if pad_buf._locked:
                unlock_memory(pad_buf.buffer)
                pad_buf._locked = False
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
