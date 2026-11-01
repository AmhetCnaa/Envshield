from __future__ import annotations

from pathlib import Path
from unittest import mock

from envshield.core.editor import (
    build_hardened_editor_command,
    edit_vault,
    get_default_editor,
    get_ephemeral_ram_base,
    shred_directory_contents,
)
from envshield.core.vault import seal_file, unseal_to_memory


def test_get_default_editor(monkeypatch):
    monkeypatch.setenv("EDITOR", "custom_nano")
    assert get_default_editor() == "custom_nano"


def test_build_hardened_editor_command():
    target = Path("/tmp/vault.env")
    vim_cmd = build_hardened_editor_command("vim", target)
    assert vim_cmd[0] == "vim"
    assert "-n" in vim_cmd
    assert "-i" in vim_cmd
    assert "NONE" in vim_cmd
    assert str(target) == vim_cmd[-1]

    nvim_cmd = build_hardened_editor_command("/usr/bin/nvim", target)
    assert "-n" in nvim_cmd

    nano_cmd = build_hardened_editor_command("nano", target)
    assert nano_cmd == ["nano", str(target)]


def test_shred_directory_contents(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    main_file = sandbox / "vault.env"
    swap_file = sandbox / ".vault.env.swp"
    backup_file = sandbox / "vault.env~"
    main_file.write_text("SECRET=1", encoding="utf-8")
    swap_file.write_bytes(b"VIM_SWAP_PLAINTEXT_LEAK")
    backup_file.write_text("SECRET=OLD", encoding="utf-8")

    shred_directory_contents(sandbox)
    assert not sandbox.exists()
    assert not main_file.exists()
    assert not swap_file.exists()
    assert not backup_file.exists()


def test_get_ephemeral_ram_base():
    base = get_ephemeral_ram_base()
    assert base is None or isinstance(base, Path)


def test_edit_vault_in_place(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_URL=https://dev.example.com\n", encoding="utf-8")
    enc_file = tmp_path / ".env.enc"
    seal_file(env_file, enc_file, "edit_pass")

    # Mock editor process to append a line to the file and also create a swap artifact
    def mock_editor_exec(cmd, **kwargs):
        path = Path(cmd[-1])
        with open(path, "a", encoding="utf-8") as f:
            f.write("MODIFIED=1\n")
        # Simulate rogue editor leaving a .swp file in the same directory
        (path.parent / ".vault.env.swp").write_bytes(b"LEAKED_SWAP_DATA")
        res = mock.MagicMock()
        res.returncode = 0
        return res

    with mock.patch("subprocess.run", side_effect=mock_editor_exec):
        modified = edit_vault(enc_file, password="edit_pass", editor="mock_edit")
        assert modified is True

    # Verify unsealed in-memory has the modified variable
    secrets = unseal_to_memory(enc_file, password="edit_pass")
    assert secrets["API_URL"] == "https://dev.example.com"
    assert secrets["MODIFIED"] == "1"

