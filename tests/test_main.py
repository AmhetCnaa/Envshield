def my_exit(code=0): raise SystemExit(code)
import pytest
import sys
from unittest import mock
from envshield.cli.main import main, scan_file
from envshield.core.models import ScanResult
from envshield.scanners.regex import RegexScanner

def test_scan_file(tmp_path):
    result = ScanResult()
    test_file = tmp_path / "test.py"
    test_file.write_text("AKIAIOSFODNN7EXAMPLE\n")
    
    scan_file(str(test_file), [RegexScanner()], result)
    assert result.scanned_files_count == 1
    assert len(result.findings) == 1

@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("envshield.cli.main.Console.print")
def test_main_no_args_clean(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dummy.txt").write_text("hello")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("sys.argv", ["envshield", str(tmp_path)]):
            main()
    assert e.value.code == 0

@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("envshield.cli.main.Console.print")
def test_main_issues_found(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.py").write_text("AKIAIOSFODNN7EXAMPLE\n")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("sys.argv", ["envshield", str(tmp_path)]):
            main()
    assert e.value.code == 1
    
@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("envshield.cli.main.Console.print")
def test_main_staged(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.py").write_text("AKIAIOSFODNN7EXAMPLE\n")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("envshield.cli.main.get_staged_files", return_value=[str(tmp_path / "test.py")]):
            with mock.patch("sys.argv", ["envshield", "--staged"]):
                main()
    assert e.value.code == 1

@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("builtins.print")
def test_main_json_format(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.py").write_text("AKIAIOSFODNN7EXAMPLE\n")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("sys.argv", ["envshield", str(tmp_path), "--format", "json"]):
            main()
    assert e.value.code == 1

@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("builtins.print")
def test_main_sarif_format(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "test.py").write_text("AKIAIOSFODNN7EXAMPLE\n")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("sys.argv", ["envshield", str(tmp_path), "--format", "sarif"]):
            main()
    assert e.value.code == 1

@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("envshield.cli.main.Console.print")
def test_main_install_hook(mock_print, mock_exit):
    with pytest.raises(SystemExit) as e:
        with mock.patch("envshield.cli.main.install_pre_commit_hook", return_value=True):
            with mock.patch("sys.argv", ["envshield", "--install-hook"]):
                main()
    assert e.value.code == 0
    
@mock.patch("sys.exit", side_effect=my_exit)
@mock.patch("envshield.cli.main.Console.print")
def test_main_env_validation(mock_print, mock_exit, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.example").write_text("PORT=8080\n")
    (tmp_path / ".env").write_text("PORT=abc\n")
    
    with pytest.raises(SystemExit) as e:
        with mock.patch("sys.argv", ["envshield", str(tmp_path)]):
            main()
    assert e.value.code == 1