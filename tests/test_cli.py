import json

from envshield.core.models import Finding, ScanResult, Severity
from envshield.utils.formatters import format_json, format_sarif
from envshield.utils.ignore import IgnoreManager
from envshield.utils.masking import mask_secret


def test_mask_secret():
    assert mask_secret("short") == "***"
    assert mask_secret("longersecretkey") == "lon...key"


def test_format_json():
    result = ScanResult()
    result.add_finding(Finding("file.py", 1, "ID", "Desc", Severity.HIGH, "secret", "fix it"))
    output = format_json(result)
    data = json.loads(output)
    assert data["findings_count"] == 1
    assert data["findings"][0]["severity"] == "HIGH"


def test_format_sarif():
    result = ScanResult()
    result.add_finding(Finding("file.py", 1, "ID", "Desc", Severity.HIGH, "secret", "fix it"))
    output = format_sarif(result)
    data = json.loads(output)
    assert "runs" in data
    assert len(data["runs"][0]["results"]) == 1


def test_ignore_manager(tmp_path):
    # Mock an ignore file
    ignore_file = tmp_path / ".envshieldignore"
    ignore_file.write_text("*.txt\nignored_dir/*")

    manager = IgnoreManager(str(tmp_path))
    assert manager.is_ignored(str(tmp_path / "test.txt")) == True
    assert manager.is_ignored(str(tmp_path / "test.py")) == False
    assert manager.is_ignored(str(tmp_path / "ignored_dir" / "file.py")) == True
