from __future__ import annotations

import shutil
import sys

from envshield.core.runner import execute_with_env


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
) -> list[str]:
    """
    Constructs the docker run command with in-memory secrets injected.

    Standard mode:
      Injects secrets as `-e KEY=VALUE` arguments directly into the docker run command
      without writing any plaintext .env file to disk.

    Stealth mode:
      Mounts an isolated RAM tmpfs inside the container at /run/secrets
      to prevent secret exposure in `docker inspect <container>`.
    """
    cmd: list[str] = ["docker"]

    # If first argument is not already 'run', ensure 'run' is present
    subcmd = determine_docker_subcommand(docker_args)
    injected_args: list[str] = []

    if subcmd == "compose":
        # Docker compose reads host environment directly; no need to pollute CLI args
        return ["docker"] + docker_args

    if not stealth:
        # Standard mode: Pass secrets as -e KEY=VAL directly to docker run
        for key, val in secrets.items():
            injected_args.extend(["-e", f"{key}={val}"])
    else:
        # Stealth mode: Mount in-memory tmpfs inside container at /run/secrets
        # Prevents variables from appearing in `docker inspect <container_id>` Config.Env
        injected_args.extend(
            [
                "--mount",
                "type=tmpfs,destination=/run/secrets,tmpfs-mode=0700",
            ]
        )

    # Find the position where options end and the image name begins
    # Insert injected_args right after the 'run' subcommand
    result_args: list[str] = []
    run_found = False

    for arg in docker_args:
        result_args.append(arg)
        if not run_found and arg == "run":
            run_found = True
            result_args.extend(injected_args)

    if not run_found:
        # If 'run' wasn't an explicit argument, insert at the beginning
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
    Zero disk writes: secrets are passed purely in RAM.
    """
    if not is_docker_available():
        sys.stderr.write(
            "envshield error: 'docker' executable not found in PATH. Please install Docker.\n"
        )
        return 1

    subcmd = determine_docker_subcommand(docker_args)
    if subcmd == "compose":
        full_command = ["docker"] + docker_args
    else:
        full_command = build_docker_run_command(docker_args, secrets, stealth=stealth)

    return execute_with_env(full_command, secrets, redact=redact)
