from __future__ import annotations

import codecs
import os
import signal
import subprocess
import sys
from typing import Any

from envshield.core.redactor import SecretRedactor

try:
    import fcntl
    import pty
    import termios
    import tty

    HAS_PTY = True
except ImportError:
    HAS_PTY = False


def is_interactive_tty() -> bool:
    """Returns True if both standard input and standard output are connected to a TTY terminal."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def setup_windows_virtual_terminal() -> bool:
    """
    Enables Virtual Terminal Processing (VT100 / ANSI escape sequence handling)
    on Windows consoles via kernel32.
    """
    if os.name != "nt":
        return True

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        STD_OUTPUT_HANDLE = -11
        STD_INPUT_HANDLE = -10
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200

        h_out = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode_out = wintypes.DWORD()
        if kernel32.GetConsoleMode(h_out, ctypes.byref(mode_out)):
            kernel32.SetConsoleMode(
                h_out, mode_out.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )

        h_in = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        mode_in = wintypes.DWORD()
        if kernel32.GetConsoleMode(h_in, ctypes.byref(mode_in)):
            kernel32.SetConsoleMode(
                h_in, mode_in.value | ENABLE_VIRTUAL_TERMINAL_INPUT
            )
        return True
    except Exception:
        return False


def _execute_posix_pty(
    command: list[str],
    merged_env: dict[str, str],
    redactor: SecretRedactor | None = None,
) -> int:
    """
    Executes a command inside a POSIX Pseudo-Terminal (PTY).
    Allows interactive subshells (bash, zsh), TUI apps (vim, htop), and REPLs (python -i, psql)
    to receive genuine TTY attributes and window resize events.
    """
    if not HAS_PTY:
        raise NotImplementedError("PTY execution is only supported on POSIX systems.")

    import select

    master_fd, slave_fd = pty.openpty()

    # Copy window size from current terminal to PTY slave
    try:
        winsize = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
    except Exception:
        pass

    def _handle_winch(signum: int, frame: Any) -> None:
        try:
            ws = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, ws)
        except Exception:
            pass

    old_handler = signal.signal(signal.SIGWINCH, _handle_winch)
    old_term_settings = None
    slave_closed = False
    utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def _setup_controlling_tty() -> None:
        """Creates a new session and binds stdin (slave_fd) as the controlling terminal."""
        os.setsid()
        if hasattr(termios, "TIOCSCTTY"):
            try:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except Exception:
                pass

    try:
        old_term_settings = termios.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())

        proc = subprocess.Popen(
            command,
            env=merged_env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            preexec_fn=_setup_controlling_tty,  # noqa: PLW1509
        )

        os.close(slave_fd)  # Close slave in parent; child keeps it open
        slave_closed = True
        merged_env.clear()

        while True:
            r, _, _ = select.select([sys.stdin.fileno(), master_fd], [], [], 0.05)

            if not r:
                # 1. Idle Flush: If the child paused output for 50ms (e.g. waiting at an interactive
                # "Password: " prompt without a trailing newline, or echoing single keystrokes),
                # flush any held lookahead buffer immediately to prevent prompt starvation.
                if redactor and redactor._pending_buffer:
                    flushed = redactor.redact_chunk("", is_eof=True)
                    if flushed:
                        os.write(sys.stdout.fileno(), flushed.encode("utf-8"))

                # 2. Drain-First Exit Check: Only break when `master_fd` has no unread data left
                # AND the child process has terminated, preventing output truncation on fast commands.
                if proc.poll() is not None:
                    break
                continue

            if sys.stdin.fileno() in r:
                # Forward user keystrokes into PTY master
                try:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if not data:
                        break
                    os.write(master_fd, data)
                except OSError:
                    break

            if master_fd in r:
                # Read from PTY master and display to user
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    if redactor and redactor.pattern:
                        text = utf8_decoder.decode(data, final=False)
                        if text:
                            sanitized = redactor.redact_chunk(text, is_eof=False)
                            if sanitized:
                                os.write(sys.stdout.fileno(), sanitized.encode("utf-8"))
                    else:
                        os.write(sys.stdout.fileno(), data)
                except OSError:
                    break

        if redactor and redactor.pattern:
            rem_utf8 = utf8_decoder.decode(b"", final=True)
            tail = redactor.redact_chunk(rem_utf8, is_eof=True)
            if tail:
                os.write(sys.stdout.fileno(), tail.encode("utf-8"))

        proc.wait()
        return proc.returncode

    finally:
        signal.signal(signal.SIGWINCH, old_handler)
        if old_term_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term_settings)
            except Exception:
                pass
        if not slave_closed:
            try:
                os.close(slave_fd)
            except Exception:
                pass
        try:
            os.close(master_fd)
        except Exception:
            pass



def _execute_windows_interactive(
    command: list[str],
    merged_env: dict[str, str],
) -> int:
    """
    Executes an interactive command on Windows with direct console handles attached,
    preserving prompt editing, arrow keys, and VT100 colors.
    """
    setup_windows_virtual_terminal()
    try:
        # None for stdin/stdout/stderr allows child to directly attach to the active console
        result = subprocess.run(
            command,
            env=merged_env,
            stdin=None,
            stdout=None,
            stderr=None,
            check=False,
        )
        return result.returncode
    except KeyboardInterrupt:
        return 130


def execute_interactive(
    command: list[str],
    secrets: dict[str, str],
    redact: bool = True,
) -> int:
    """
    Executes a command with TTY/PTY capabilities so interactive sessions
    (shells, REPLs, database CLIs, full-screen editors) function without degradation.
    """
    if not command:
        return 0

    merged_env = os.environ.copy()
    merged_env.update(secrets)

    redactor = SecretRedactor(secrets) if redact else None
    secrets.clear()

    try:
        if os.name != "nt" and HAS_PTY and is_interactive_tty():
            return _execute_posix_pty(command, merged_env, redactor=redactor)

        if os.name == "nt" and is_interactive_tty():
            return _execute_windows_interactive(command, merged_env)

        # Fallback to standard runner
        from envshield.core.runner import execute_with_env

        return execute_with_env(command, merged_env, redact=redact)
    finally:
        if redactor is not None:
            redactor.close()
        merged_env.clear()

