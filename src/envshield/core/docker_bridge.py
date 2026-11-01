from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from envshield.core.editor import get_ephemeral_ram_base, shred_directory_contents
from envshield.core.runner import execute_with_env


def _write_restricted_file(target: Path, content: str) -> None:
    """
    Atomically creates and writes a file with strict 0o400 (read-only owner) permissions
    at creation time via os.open() to eliminate any TOCTOU permission window.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(target, flags, 0o400)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    if sys.platform != "win32":
        try:
            os.chmod(target, 0o400)
        except OSError:
            pass


def is_docker_available() -> bool:


    """Checks whether the docker CLI executable is installed and available in PATH."""
    return shutil.which("docker") is not None


def determine_docker_subcommand(docker_args: list[str]) -> str:
    """
    Identifies the Docker subcommand (e.g. 'run', 'compose', 'build').
    Handles global docker flags that may precede the subcommand (e.g. 'docker -D run').
    """
    skip_next = False
    for arg in docker_args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-H", "--host", "-c", "--context", "-l", "--log-level"):
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg.lower()
    return "run"


def build_docker_run_command(
    docker_args: list[str],
    secrets: dict[str, str],
    stealth: bool = False,
    stealth_dir: Path | None = None,
) -> list[str]:
    """
    Constructs the docker run command with in-memory secrets injected.

    Standard mode (`stealth=False`):
      Passes ONLY `-e KEY` (key name without value!) on the CLI argument vector (`argv`).
      Docker CLI automatically inherits the secret values from its own process environment
      (`merged_env` in `execute_with_env`), completely preventing `ps aux` / `/proc/<pid>/cmdline`
      from leaking secret values to other local OS users!

    Stealth mode (`stealth=True`):
      Mounts an isolated RAM-backed host directory (`/dev/shm` when available) read-only into
      the container at `/run/secrets` (plus a tmpfs overlay if no host stealth_dir is supplied),
      preventing variables from appearing in `docker inspect <container_id>` `Config.Env`.
    """
    cmd: list[str] = ["docker"]

    subcmd = determine_docker_subcommand(docker_args)
    injected_args: list[str] = []

    if subcmd == "compose":
        # Docker compose reads host environment directly; no need to pollute CLI args
        return ["docker"] + docker_args

    if not stealth:
        # Standard mode: Pass ONLY `-e KEY` (never `-e KEY=VAL`!) so `ps aux` / `/proc/<pid>/cmdline`
        # never exposes plaintext secret values on the host OS.
        for key in secrets:
            injected_args.extend(["-e", key])
    else:
        if stealth_dir is not None:
            injected_args.extend(
                [
                    "-v",
                    f"{stealth_dir.resolve()}:/run/secrets:ro",
                ]
            )
        else:
            injected_args.extend(
                [
                    "--mount",
                    "type=tmpfs,destination=/run/secrets,tmpfs-mode=0700",
                ]
            )

    result_args: list[str] = []
    run_found = False

    for arg in docker_args:
        result_args.append(arg)
        if not run_found and arg == "run":
            run_found = True
            result_args.extend(injected_args)

    if not run_found:
        result_args = injected_args + result_args

    return cmd + result_args


def execute_docker_with_secrets(
    docker_args: list[str],
    secrets: dict[str, str],
    stealth: bool = False,
    redact: bool = True,
) -> int:
    """
    Executes a Docker command with secrets injected into memory and
    real-time live stream redaction active on stdout/stderr.
    """
    if not is_docker_available():
        sys.stderr.write(
            "envshield error: 'docker' executable not found in PATH. Please install Docker.\n"
        )
        return 1

    subcmd = determine_docker_subcommand(docker_args)
    if subcmd == "compose":
        full_command = ["docker"] + docker_args
        return execute_with_env(full_command, secrets, redact=redact)

    if stealth:
        ram_base = get_ephemeral_ram_base()
        stealth_dir = Path(
            tempfile.mkdtemp(prefix=f".envshield_docker_secrets_{os.getpid()}_", dir=str(ram_base))
        )
        if sys.platform != "win32":
            try:
                os.chmod(stealth_dir, 0o700)
            except OSError:
                pass
        try:
            # Materialize individual secret files (/run/secrets/<KEY>) and combined .env inside RAM dir
            # using direct os.open(..., 0o400) to avoid any TOCTOU permission gap.
            env_lines: list[str] = []
            for k, v in secrets.items():
                safe_name = Path(k).name
                if safe_name and safe_name not in (".", ".."):
                    sec_file = stealth_dir / safe_name
                    _write_restricted_file(sec_file, v)
                env_lines.append(f"{k}={v}")

            combined_env = stealth_dir / ".env"
            _write_restricted_file(combined_env, "\n".join(env_lines) + "\n")

            full_command = build_docker_run_command(
                docker_args, secrets, stealth=True, stealth_dir=stealth_dir
            )
            return execute_with_env(full_command, secrets, redact=redact)
        finally:
            shred_directory_contents(stealth_dir)


    full_command = build_docker_run_command(docker_args, secrets, stealth=False)
    return execute_with_env(full_command, secrets, redact=redact)

