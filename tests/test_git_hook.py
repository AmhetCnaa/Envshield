from __future__ import annotations

from pathlib import Path

from envshield.core.git_hook import (
    install_hook,
    run_pre_commit_scan,
    uninstall_hook,
)


def test_install_and_uninstall_hook(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    success, msg = install_hook(tmp_path)
    assert success is True
    assert "installed at" in msg

    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.is_file()
    assert "EnvShield" in hook_file.read_text(encoding="utf-8")

    # Second install without force
    success, msg = install_hook(tmp_path, force=False)
    assert success is True
    assert "already installed" in msg

    # Uninstall
    success, msg = uninstall_hook(tmp_path)
    assert success is True
    assert not hook_file.exists()


def test_run_pre_commit_scan_empty(monkeypatch) -> None:
    # No staged files
    monkeypatch.setattr("envshield.core.git_hook.get_staged_env_files", list)
    ret = run_pre_commit_scan(interactive=False)
    assert ret == 0


def test_run_pre_commit_scan_non_interactive_abort(monkeypatch) -> None:
    monkeypatch.setattr("envshield.core.git_hook.get_staged_env_files", lambda: [".env"])
    ret = run_pre_commit_scan(interactive=False)
    assert ret == 1
