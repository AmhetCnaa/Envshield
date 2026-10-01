from unittest import mock

from envshield.utils.git import get_staged_files, install_pre_commit_hook


@mock.patch("subprocess.run")
def test_get_staged_files(mock_run):
    mock_result = mock.Mock()
    mock_result.stdout = "file1.py\nfile2.txt\n"
    mock_run.return_value = mock_result
    
    with mock.patch("os.path.isfile", return_value=True):
        files = get_staged_files()
        assert len(files) == 2
        assert "file1.py" in files

@mock.patch("subprocess.run")
@mock.patch("builtins.open", new_callable=mock.mock_open)
@mock.patch("os.makedirs")
def test_install_pre_commit_hook(mock_makedirs, mock_open, mock_run):
    mock_result = mock.Mock()
    mock_result.returncode = 0
    mock_result.stdout = "/path/to/.git\n"
    mock_run.return_value = mock_result
    
    with mock.patch("os.chmod"):
        success = install_pre_commit_hook()
        assert success == True
        mock_open.assert_called_once()
