from __future__ import annotations

from pathlib import Path

import pytest

from envshield.cli.main import main
from envshield.core.drift import detect_secret_drift, scan_codebase_env_vars
from envshield.core.vault import seal_file


def test_scan_codebase_env_vars(tmp_path: Path) -> None:
    code_dir = tmp_path / "src"
    code_dir.mkdir()

    py_file = code_dir / "app.py"
    py_file.write_text(
        'import os\n'
        'api_key = os.environ["STRIPE_SECRET_KEY"]\n'
        'db = os.getenv("DATABASE_URL")\n'
        'port = os.environ.get("PORT", "8080")\n',
        encoding="utf-8",
    )

    js_file = code_dir / "index.js"
    js_file.write_text(
        'const redis = process.env.REDIS_HOST;\n'
        'const secret = process.env["JWT_PRIVATE_KEY"];\n',
        encoding="utf-8",
    )

    vars_found, count = scan_codebase_env_vars(tmp_path)
    assert count == 2
    assert "STRIPE_SECRET_KEY" in vars_found
    assert "DATABASE_URL" in vars_found
    assert "PORT" in vars_found
    assert "REDIS_HOST" in vars_found
    assert "JWT_PRIVATE_KEY" in vars_found


def test_detect_secret_drift(tmp_path: Path) -> None:
    # 1. Create source code referencing 2 variables
    src_file = tmp_path / "service.py"
    src_file.write_text(
        'import os\n'
        'k1 = os.environ["ACTIVE_API_KEY"]\n'
        'k2 = os.environ["NEW_FEATURE_FLAG"]\n',  # NEW_FEATURE_FLAG missing in vault!
        encoding="utf-8",
    )

    # 2. Create .env.example
    example_file = tmp_path / ".env.example"
    example_file.write_text(
        "ACTIVE_API_KEY=your_key_here\n"
        "OPTIONAL_TRACKING_ID=12345\n",
        encoding="utf-8",
    )

    # 3. Create .env with profiles and seal it
    env_content = (
        "[development]\n"
        "ACTIVE_API_KEY=dev_key_123\n"
        "UNUSED_OLD_VAR=dead_value\n"
        "DEV_ONLY_FLAG=true\n"
        "[production]\n"
        "ACTIVE_API_KEY=prod_key_999\n"
        "UNUSED_OLD_VAR=dead_value\n"
    )
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    seal_file(env_file, vault_file, password="test_password_123")

    report = detect_secret_drift(
        root_dir=tmp_path,
        vault_path=vault_file,
        example_path=example_file,
        password="test_password_123",
    )

    assert report.has_issues() is True

    categories = {f.category for f in report.findings}
    assert "MISSING_IN_VAULT" in categories  # NEW_FEATURE_FLAG and OPTIONAL_TRACKING_ID
    assert "DEAD_SECRET" in categories       # UNUSED_OLD_VAR
    assert "PROFILE_MISMATCH" in categories  # DEV_ONLY_FLAG in dev but missing in prod

    missing_keys = {f.key for f in report.findings if f.category == "MISSING_IN_VAULT"}
    assert "NEW_FEATURE_FLAG" in missing_keys

    dead_keys = {f.key for f in report.findings if f.category == "DEAD_SECRET"}
    assert "UNUSED_OLD_VAR" in dead_keys


def test_cli_drift_clean_and_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    # Clean codebase & vault
    code_file = tmp_path / "main.py"
    code_file.write_text('import os\nx = os.environ["APP_KEY"]\n', encoding="utf-8")

    env_file = tmp_path / ".env"
    env_file.write_text("APP_KEY=clean_secret\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"

    seal_file(env_file, vault_file, password="pass")

    # Clean run
    with pytest.raises(SystemExit) as exc:
        main(["drift", str(vault_file), "-p", "pass"])
    assert exc.value.code == 0

    # Introduce drift in code
    code_file.write_text('import os\nx = os.environ["APP_KEY"]\ny = os.environ["UNSAVED_API_KEY"]\n', encoding="utf-8")

    # Run with --ci (should exit 1)
    with pytest.raises(SystemExit) as exc:
        main(["drift", str(vault_file), "-p", "pass", "--ci"])
    assert exc.value.code == 1
