from __future__ import annotations

import getpass
import os
import stat
import subprocess
from pathlib import Path

from rich.console import Console

from envshield.core.vault import seal_file, shred_file

HOOK_SCRIPT = """#!/bin/sh
# EnvShield Self-Healing Pre-Commit Hook
# Prevents accidental secret leaks and automatically seals .env files

if [ -t 0 ]; then
    exec < /dev/tty
    envshield hook run --interactive
else
    envshield hook run --non-interactive
fi
"""


def find_git_hooks_dir(start_path: Path | str | None = None) -> Path | None:
    """Locates the .git/hooks directory for the current repository."""
    current = Path(start_path or os.getcwd()).resolve()
    for parent in [current] + list(current.parents):
        git_dir = parent / ".git"
        if git_dir.is_dir():
            hooks_dir = git_dir / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            return hooks_dir
    return None


def install_hook(git_dir: Path | str | None = None, force: bool = False) -> tuple[bool, str]:
    """Installs the EnvShield self-healing pre-commit hook."""
    hooks_dir = find_git_hooks_dir(git_dir)
    if not hooks_dir:
        return False, "Not inside a git repository."

    hook_file = hooks_dir / "pre-commit"
    if hook_file.exists() and not force:
        # Check if already installed
        try:
            content = hook_file.read_text(encoding="utf-8")
            if "EnvShield" in content:
                return True, "EnvShield hook is already installed."
        except Exception:
            pass
        return False, f"Existing pre-commit hook found at '{hook_file}'. Use --force to overwrite."

    try:
        hook_file.write_text(HOOK_SCRIPT, encoding="utf-8")
        # Set executable permissions (chmod +x)
        current_mode = hook_file.stat().st_mode
        hook_file.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True, f"EnvShield self-healing hook installed at '{hook_file}'."
    except Exception as exc:
        return False, f"Failed to install hook: {exc}"


def uninstall_hook(git_dir: Path | str | None = None) -> tuple[bool, str]:
    """Uninstalls the EnvShield pre-commit hook."""
    hooks_dir = find_git_hooks_dir(git_dir)
    if not hooks_dir:
        return False, "Not inside a git repository."

    hook_file = hooks_dir / "pre-commit"
    if not hook_file.exists():
        return False, "No pre-commit hook found."

    try:
        content = hook_file.read_text(encoding="utf-8")
        if "EnvShield" not in content:
            return (
                False,
                "Existing pre-commit hook was not installed by EnvShield. Skipping removal.",
            )
        hook_file.unlink()
        return True, "EnvShield pre-commit hook uninstalled successfully."
    except Exception as exc:
        return False, f"Failed to remove hook: {exc}"


def get_staged_env_files() -> list[str]:
    """Retrieves staged files that match unencrypted environment patterns."""
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3.0,
        )
        if res.returncode != 0:
            return []

        staged = [f.strip() for f in res.stdout.splitlines() if f.strip()]
        leak_candidates: list[str] = []

        safe_suffixes = (".enc", ".example", ".sample", ".template", ".vault")

        for f in staged:
            lower = f.lower()
            if any(lower.endswith(s) for s in safe_suffixes):
                continue
            name = Path(f).name.lower()
            if name.startswith(".env") or name == "secrets.json" or name == "secrets.toml":
                leak_candidates.append(f)

        return leak_candidates
    except Exception:
        return []


def run_pre_commit_scan(
    interactive: bool = True,
    console: Console | None = None,
) -> int:
    """
    Executes pre-commit scanning on staged files.
    If plaintext .env files are found, in interactive mode offers self-healing:
    Encrypts with AES-256-GCM, shreds the unencrypted file, and stages the vault.
    """
    c = console or Console()
    staged_files = get_staged_env_files()

    if not staged_files:
        return 0

    c.print(
        f"\n[bold yellow]EnvShield Hook Alert:[/bold yellow] Found {len(staged_files)} unencrypted secret file(s) in git staging:"
    )
    for f in staged_files:
        c.print(f"  [red]• {f}[/red]")

    if not interactive:
        c.print(
            "[bold red]Commit aborted: Unencrypted secret files detected in staging.[/bold red]"
        )
        c.print("To fix, run: [cyan]envshield seal <file> --shred && git add <file>.enc[/cyan]\n")
        return 1

    c.print("\n[bold cyan]EnvShield Self-Healing Protection:[/bold cyan]")
    try:
        answer = (
            input(
                "Would you like to automatically seal these files and stage the encrypted vaults? [Y/n]: "
            )
            .strip()
            .lower()
        )
    except (EOFError, KeyboardInterrupt):
        c.print("\n[red]Aborted.[/red]")
        return 1

    if answer not in ("", "y", "yes"):
        c.print(
            "[red]Commit aborted. Please remove or encrypt secret files before committing.[/red]"
        )
        return 1

    # Ask for password once for all detected files
    try:
        password = getpass.getpass("Enter master password to seal files: ")
        if not password:
            c.print("[red]Password cannot be empty. Aborted.[/red]")
            return 1
    except (EOFError, KeyboardInterrupt):
        return 1

    for f in staged_files:
        source_path = Path(f)
        target_path = Path(f"{f}.enc")

        c.print(f"Sealing [cyan]{source_path}[/cyan] -> [green]{target_path}[/green]...")
        try:
            seal_file(source_path, target_path, password=password)
            shred_file(source_path)

            # Unstage unencrypted file (using `--` separator to prevent option injection on filenames starting with `-`)
            subprocess.run(
                ["git", "rm", "--cached", "--", str(source_path)], check=False, capture_output=True
            )
            # Stage encrypted vault
            subprocess.run(["git", "add", "--", str(target_path)], check=False, capture_output=True)

            c.print(f"[green]✓ Sealed, shredded, and staged {target_path}.[/green]")
        except Exception as exc:
            c.print(f"[red]Failed to seal {source_path}: {exc}[/red]")
            return 1

    c.print("[bold green]All secrets secured! Commit proceeding safely.[/bold green]\n")
    return 0
