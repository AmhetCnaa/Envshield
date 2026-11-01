from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from envshield.core.vault import seal_payload, shred_file, unseal_raw_payload


def get_default_editor() -> str:
    """Detects available terminal or GUI editor for the current OS."""
    for env_var in ("VISUAL", "EDITOR"):
        val = os.environ.get(env_var)
        if val:
            return val

    if sys.platform == "win32":
        return "notepad"

    for candidate in ("nano", "vim", "vi"):
        if shutil.which(candidate):
            return candidate

    return "vi"


def get_ephemeral_ram_base() -> Path:
    """
    Returns an in-memory tmpfs directory (/dev/shm or XDG_RUNTIME_DIR on Linux)
    if available and writable, otherwise falls back to the system temp directory.
    """
    if sys.platform != "win32":
        for candidate in ("/dev/shm", os.environ.get("XDG_RUNTIME_DIR", "")):
            if candidate:
                p = Path(candidate)
                if p.is_dir() and os.access(p, os.W_OK | os.X_OK):
                    return p
    return Path(tempfile.gettempdir())


def build_hardened_editor_command(editor_cmd: str, target_file: Path) -> list[str]:
    """
    Constructs editor command with anti-swap, anti-backup, and anti-undofile flags
    to prevent editors like vim/nvim from leaking plaintext artifacts onto disk.
    """
    parts = shlex.split(editor_cmd, posix=(sys.platform != "win32"))
    if not parts:
        parts = [editor_cmd]

    exe_name = Path(parts[0]).stem.lower()
    if exe_name in ("vim", "nvim", "vi"):
        return [
            *parts,
            "-n",  # No swap file (memory only)
            "-i",
            "NONE",  # No .viminfo state
            "--cmd",
            "set nobackup nowritebackup noswapfile noundofile",
            str(target_file),
        ]

    return [*parts, str(target_file)]


def shred_directory_contents(directory: Path) -> None:
    """
    Forensically shreds all files inside an isolated temporary directory
    (including any editor-generated .swp, ~, .bak, or undo files) before removing it.
    """
    if not directory.is_dir():
        return

    for root, _dirs, files in os.walk(directory, topdown=False):
        for name in files:
            file_path = Path(root) / name
            try:
                shred_file(file_path)
            except Exception:
                try:
                    file_path.unlink(missing_ok=True)
                except Exception:
                    pass
    try:
        shutil.rmtree(directory, ignore_errors=True)
    except Exception:
        pass


def edit_vault(
    vault_path: Path | str,
    password: str | None = None,
    identity_path: str | Path | None = None,
    editor: str | None = None,
) -> bool:
    """
    Safely edits an encrypted vault in-place inside an isolated RAM-backed (/dev/shm)
    sandbox directory with swap suppression and full multi-file forensic shredding on exit.
    Returns True if changes were saved, False if cancelled or unchanged.
    """
    path = Path(vault_path)
    if not path.is_file():
        raise FileNotFoundError(f"Vault file '{path}' not found.")

    plaintext, fmt = unseal_raw_payload(path, password=password, identity_path=identity_path)
    editor_cmd = editor or get_default_editor()

    # Create an isolated 0700 directory inside /dev/shm (if available) so any
    # editor backup/swap files are contained and shredded together on exit.
    ram_base = get_ephemeral_ram_base()
    sandbox_dir = Path(
        tempfile.mkdtemp(prefix=f".envshield_sandbox_{os.getpid()}_", dir=str(ram_base))
    )
    if sys.platform != "win32":
        try:
            os.chmod(sandbox_dir, 0o700)
        except OSError:
            pass

    suffix = f".{fmt}" if fmt != "env" else ".env"
    temp_file = sandbox_dir / f"vault_buffer{suffix}"

    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = 0o600
        fd = os.open(temp_file, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(plaintext)

        cmd_args = build_hardened_editor_command(editor_cmd, temp_file)
        proc = subprocess.run(cmd_args, check=False)
        if proc.returncode != 0:
            return False

        if not temp_file.is_file():
            return False

        new_content = temp_file.read_text(encoding="utf-8")

        if new_content != plaintext:
            from envshield.core.kms import list_kms_slots
            from envshield.core.recipients import Recipient
            from envshield.core.team import get_all_team_recipients

            recipients: list[Recipient] = list(get_all_team_recipients(path.parent))
            for slot in list_kms_slots(path):
                recipients.append(Recipient.from_string(slot["key_spec"]))

            seal_payload(
                payload_content=new_content,
                target_path=path,
                password=password,
                recipients=recipients if recipients else None,
                format_type=fmt,
            )
            return True

        return False
    finally:
        shred_directory_contents(sandbox_dir)
