from __future__ import annotations

from unittest import mock

from envshield.core.editor import edit_vault, get_default_editor
from envshield.core.vault import seal_file, unseal_to_memory


def test_get_default_editor(monkeypatch):
    monkeypatch.setenv("EDITOR", "custom_nano")
    assert get_default_editor() == "custom_nano"


def test_edit_vault_in_place(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_URL=https://dev.example.com\n", encoding="utf-8")
    enc_file = tmp_path / ".env.enc"
    seal_file(env_file, enc_file, "edit_pass")

    # Mock editor process to append a line to the file
    def mock_editor_exec(cmd, **kwargs):
        path = cmd[1]
        with open(path, "a", encoding="utf-8") as f:
            f.write("MODIFIED=1\n")
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
