from __future__ import annotations

import os
import subprocess


def execute_with_env(command: list[str], secrets: dict[str, str]) -> int:
    """
    Executes a command with secrets injected into the process environment.
    Zero-disk writes: secrets are passed directly in memory to the child process environment.
    Terminal output (stdout/stderr) streams directly to the parent terminal.
    Returns the process exit code.
    """
    if not command:
        return 0

    merged_env = os.environ.copy()
    merged_env.update(secrets)

    result = subprocess.run(command, env=merged_env, check=False)
    return result.returncode
