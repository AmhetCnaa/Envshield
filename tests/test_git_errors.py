import subprocess
from unittest import mock

from envshield.utils.git import get_staged_files, install_pre_commit_hook


@mock.patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "cmd"))
def test_get_staged_files_error(mock_run):
    assert get_staged_files() == []

@mock.patch("subprocess.run")
def test_install_pre_commit_hook_fail(mock_run):
    mock_result = mock.Mock()
    mock_result.returncode = 1
    mock_run.return_value = mock_result
    assert install_pre_commit_hook() == False
