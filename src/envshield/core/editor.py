from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from envshield.core.vault import seal_file, shred_file, unseal_raw_payload


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


def edit_vault(
    vault_path: Path | str,
    password: str | None = None,
    identity_path: str | Path | None = None,
    editor: str | None = None,
) -> bool:
    """
    Safely edits an encrypted vault in-place using an ephemeral, shredded temporary file.
    Returns True if changes were saved, False if cancelled or unchanged.
    """
    path = Path(vault_path)
    if not path.is_file():
        raise FileNotFoundError(f"Vault file '{path}' not found.")

    plaintext, fmt = unseal_raw_payload(path, password=password, identity_path=identity_path)

    # Determine editor command
    editor_cmd = editor or get_default_editor()

    # Create temporary file with restrictive permissions
    temp_dir = tempfile.gettempdir()
    suffix = f".{fmt}" if fmt != "env" else ".env"
    temp_file = Path(temp_dir) / f".envshield_edit_{os.getpid()}_{os.urandom(4).hex()}{suffix}"

    try:
        # On POSIX set 0600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        mode = 0o600
        fd = os.open(temp_file, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(plaintext)

        # Launch editor
        proc = subprocess.run([editor_cmd, str(temp_file)], check=False)
        if proc.returncode != 0:
            return False

        # Read modified content
        if not temp_file.is_file():
            return False

        new_content = temp_file.read_text(encoding="utf-8")

        # If modified, re-seal
        if new_content != plaintext:
            # Overwrite source with new content temporarily to re-seal
            seal_file(temp_file, path, password=password, format_type=fmt)
            return True

        return False
    finally:
        if temp_file.is_file():
            shred_file(temp_file)
