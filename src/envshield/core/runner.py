from __future__ import annotations

import gc
import os
import subprocess
import sys

from envshield.core.memory import ObfuscatedSecretStore, disable_core_dumps
from envshield.core.redactor import SecretRedactor, sanitize_stream


def execute_with_env(
    command: list[str],
    secrets: dict[str, str],
    redact: bool = True,
    pty: bool = False,
) -> int:
    """
    Executes a command with secrets injected into the process environment.
    Zero-disk writes: secrets are passed directly in memory to the child process environment.
    Hardening:
      - Disables crash core dumps (RLIMIT_CORE / PR_SET_DUMPABLE / SetErrorMode).
      - Holds secrets in an XOR-masked ObfuscatedSecretStore inside locked RAM pages
        and wipes the transient environment dictionary immediately after child spawn.

    When `pty=True`, executes inside a Pseudo-Terminal (PTY) session, enabling
    interactive subshells (bash, zsh), TUI programs, and REPLs to receive native TTY controls.

    When `redact=True` (default), stdout and stderr streams are intercepted in real-time,
    and any secret values are automatically masked with [REDACTED:<KEY_NAME>] before
    being flushed to the terminal or CI/CD logs.

    Returns the child process exit code.
    """
    if not command:
        return 0

    disable_core_dumps()

    if pty:
        from envshield.core.terminal import execute_interactive

        return execute_interactive(command, secrets, redact=redact)

    with ObfuscatedSecretStore(secrets) as secret_store:
        merged_env = os.environ.copy()
        merged_env.update(secret_store.reveal_all())

        if not redact:
            try:
                result = subprocess.run(command, env=merged_env, check=False)
                return result.returncode
            finally:
                merged_env.clear()
                gc.collect()

        redactor = SecretRedactor(secret_store.reveal_all())

        # If no secrets need redaction, direct execution is fastest
        if not redactor.pattern:
            try:
                result = subprocess.run(command, env=merged_env, check=False)
                return result.returncode
            finally:
                merged_env.clear()
                gc.collect()

        try:
            proc = subprocess.Popen(
                command,
                env=merged_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,  # Line-buffered
            )
            # Clear transient cleartext env copy in parent immediately after child spawn
            merged_env.clear()
            gc.collect()

            assert proc.stdout is not None
            assert proc.stderr is not None

            t_out = sanitize_stream(proc.stdout, sys.stdout, redactor)
            t_err = sanitize_stream(proc.stderr, sys.stderr, redactor)

            exit_code = proc.wait()
            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)
            return exit_code

        except KeyboardInterrupt:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            return 130
        except Exception as exc:
            sys.stderr.write(f"envshield error executing command: {exc}\n")
            return 1
        finally:
            merged_env.clear()
            gc.collect()

