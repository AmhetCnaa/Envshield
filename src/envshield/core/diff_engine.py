from __future__ import annotations

import difflib
from pathlib import Path

from rich.console import Console

from envshield.core.vault import unseal_raw_payload


def get_file_content_in_memory(
    file_path: Path | str,
    password: str | None = None,
    identity_path: str | Path | None = None,
) -> tuple[str, str]:
    """
    Returns (content_str, label) in memory without persisting.
    If file has .enc suffix, decrypts in RAM. Otherwise reads text directly.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    if path.suffix == ".enc" or ".enc." in path.name:
        content, _ = unseal_raw_payload(path, password=password, identity_path=identity_path)
        return content, str(path)

    return path.read_text(encoding="utf-8"), str(path)


def compute_in_memory_diff(
    target_a: Path | str,
    target_b: Path | str | None = None,
    password_a: str | None = None,
    password_b: str | None = None,
    identity_path: str | Path | None = None,
) -> list[str]:
    """
    Computes unified diff between two files in RAM.
    If target_b is None, attempts to compare target_a against its unencrypted peer.
    """
    path_a = Path(target_a)

    if target_b is None:
        # If target_a is .env.enc, compare with .env if it exists
        if path_a.suffix == ".enc":
            peer = path_a.with_suffix("")
            if peer.is_file():
                path_b = peer
            else:
                raise ValueError(
                    f"No second file specified and default peer '{peer}' does not exist."
                )
        else:
            peer = Path(f"{path_a}.enc")
            if peer.is_file():
                path_b = peer
            else:
                raise ValueError(
                    f"No second file specified and encrypted peer '{peer}' does not exist."
                )
    else:
        path_b = Path(target_b)

    content_a, label_a = get_file_content_in_memory(
        path_a, password=password_a, identity_path=identity_path
    )
    content_b, label_b = get_file_content_in_memory(
        path_b, password=password_b or password_a, identity_path=identity_path
    )

    lines_a = content_a.splitlines(keepends=True)
    lines_b = content_b.splitlines(keepends=True)

    diff = list(
        difflib.unified_diff(
            lines_a,
            lines_b,
            fromfile=label_a,
            tofile=label_b,
        )
    )
    return diff


def render_diff(diff_lines: list[str], console: Console | None = None) -> None:
    """
    Prints syntax-colored unified diff to terminal using rich.
    """
    c = console or Console()

    if not diff_lines:
        c.print("[green]No differences found (files are identical in memory).[/green]")
        return

    for line in diff_lines:
        clean = line.rstrip("\r\n")
        if clean.startswith(("+++", "---")):
            c.print(f"[bold]{clean}[/bold]")
        elif clean.startswith("@@"):
            c.print(f"[cyan]{clean}[/cyan]")
        elif clean.startswith("+"):
            c.print(f"[green]{clean}[/green]")
        elif clean.startswith("-"):
            c.print(f"[red]{clean}[/red]")
        else:
            c.print(f" {clean}")
