from __future__ import annotations

import os
import subprocess
import sys

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

    When `pty=True`, executes inside a Pseudo-Terminal (PTY) session, enabling
    interactive subshells (bash, zsh), TUI programs, and REPLs to receive native TTY controls.

    When `redact=True` (default), stdout and stderr streams are intercepted in real-time,
    and any secret values are automatically masked with [REDACTED:<KEY_NAME>] before
    being flushed to the terminal or CI/CD logs.

    Returns the child process exit code.
    """
    if not command:
        return 0

    if pty:
        from envshield.core.terminal import execute_interactive

        return execute_interactive(command, secrets, redact=redact)

    merged_env = os.environ.copy()
    merged_env.update(secrets)

    if not redact:
        result = subprocess.run(command, env=merged_env, check=False)
        return result.returncode

    redactor = SecretRedactor(secrets)

    # If no secrets need redaction, direct execution is fastest
    if not redactor.pattern:
        result = subprocess.run(command, env=merged_env, check=False)
        return result.returncode

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
