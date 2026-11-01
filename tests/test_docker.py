from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from envshield.cli.main import main
from envshield.core.docker_bridge import (
    build_docker_run_command,
    determine_docker_subcommand,
    execute_docker_with_secrets,
    is_docker_available,
)
from envshield.core.vault import seal_file


def my_exit(code=0):
    raise SystemExit(code)


def test_determine_docker_subcommand() -> None:
    assert determine_docker_subcommand(["run", "nginx"]) == "run"
    assert determine_docker_subcommand(["compose", "up", "-d"]) == "compose"
    assert determine_docker_subcommand(["-H", "tcp://1.2.3.4:2375", "run", "alpine"]) == "run"
    assert determine_docker_subcommand(["--context", "prod", "compose", "ps"]) == "compose"


def test_build_docker_run_command_standard() -> None:
    secrets = {"DB_PASS": "secret123", "API_KEY": "ak_456"}
    args = ["run", "-d", "-p", "80:80", "my-app:latest"]

    cmd = build_docker_run_command(args, secrets, stealth=False)
    assert cmd[0] == "docker"
    assert "run" in cmd
    assert "-e" in cmd
    # Critical security invariant: ONLY `-e KEY` is passed in argv (never `-e KEY=VAL`),
    # preventing secret leaks in `ps aux` / `/proc/<pid>/cmdline`.
    assert "DB_PASS" in cmd
    assert "API_KEY" in cmd
    assert "DB_PASS=secret123" not in cmd
    assert "API_KEY=ak_456" not in cmd
    assert "secret123" not in " ".join(cmd)
    assert "my-app:latest" in cmd



def test_build_docker_run_command_stealth() -> None:
    secrets = {"SECRET": "hidden"}
    args = ["run", "my-app"]

    cmd = build_docker_run_command(args, secrets, stealth=True)
    assert cmd[0] == "docker"
    assert "--mount" in cmd
    assert "type=tmpfs,destination=/run/secrets,tmpfs-mode=0700" in cmd
    # In stealth mode, -e SECRET=hidden is NOT in the command line (hides from docker inspect)
    assert "SECRET=hidden" not in cmd


def test_build_docker_command_compose() -> None:
    secrets = {"COMPOSE_SECRET": "abc"}
    args = ["compose", "up", "-d"]

    cmd = build_docker_run_command(args, secrets, stealth=False)
    # Compose passes secrets via environment directly, not CLI args
    assert cmd == ["docker", "compose", "up", "-d"]


def test_execute_docker_missing_executable(monkeypatch, capsys) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert is_docker_available() is False

    ret = execute_docker_with_secrets(["run", "nginx"], {"KEY": "VAL"})
    assert ret == 1
    _, err = capsys.readouterr()
    assert "'docker' executable not found" in err


def test_execute_docker_mocked_success(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")

    # Mock execute_with_env
    mock_exec = mock.MagicMock(return_value=0)
    monkeypatch.setattr("envshield.core.docker_bridge.execute_with_env", mock_exec)

    secrets = {"DATABASE_URL": "postgres://localhost"}
    ret = execute_docker_with_secrets(["compose", "up"], secrets)
    assert ret == 0

    mock_exec.assert_called_once()
    called_cmd = mock_exec.call_args[0][0]
    called_secrets = mock_exec.call_args[0][1]
    assert called_cmd == ["docker", "compose", "up"]
    assert called_secrets == secrets


def test_execute_docker_stealth_materializes_and_shreds_ram_secrets(monkeypatch) -> None:
    """
    Verifies that stealth mode populates an isolated ephemeral directory with
    `/run/secrets/<KEY>` files, mounts it read-only (`:ro`), and forensically shreds
    the directory immediately after container exit.
    """
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
    captured_mount_dir: list[Path] = []

    def fake_execute_with_env(cmd: list[str], secrets: dict[str, str], redact: bool = True) -> int:
        # Find the `-v <host_dir>:/run/secrets:ro` argument and verify files exist inside during run
        assert "-v" in cmd
        v_idx = cmd.index("-v")
        mount_spec = cmd[v_idx + 1]
        assert mount_spec.endswith(":/run/secrets:ro")
        host_dir = Path(mount_spec[: -len(":/run/secrets:ro")])
        assert host_dir.is_dir()
        assert (host_dir / "DB_PASS").read_text(encoding="utf-8") == "stealth_secret_val"
        assert "DB_PASS=stealth_secret_val" in (host_dir / ".env").read_text(encoding="utf-8")
        captured_mount_dir.append(host_dir)
        return 0

    monkeypatch.setattr("envshield.core.docker_bridge.execute_with_env", fake_execute_with_env)
    ret = execute_docker_with_secrets(
        ["run", "alpine"], {"DB_PASS": "stealth_secret_val"}, stealth=True
    )
    assert ret == 0
    assert len(captured_mount_dir) == 1
    # Directory must be completely shredded and removed on exit
    assert not captured_mount_dir[0].exists()



@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_docker_run_mocked(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("CONTAINER_PORT=8080\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "docker_pass")

    monkeypatch.setenv("ENVSHIELD_KEY", "docker_pass")
    mock_exec = mock.MagicMock(return_value=0)
    monkeypatch.setattr("envshield.cli.main.execute_docker_with_secrets", mock_exec)

    with pytest.raises(SystemExit) as exc:
        main(["docker", "run", "-d", "-p", "80:80", "nginx"])
    assert exc.value.code == 0

    mock_exec.assert_called_once()
    assert mock_exec.call_args[1]["stealth"] is False
    assert mock_exec.call_args[1]["secrets"]["CONTAINER_PORT"] == "8080"


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_docker_stealth_flag(mock_exit, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("CLASSIFIED_TOKEN=xyz\n", encoding="utf-8")
    seal_file(env_file, tmp_path / ".env.enc", "docker_pass")

    monkeypatch.setenv("ENVSHIELD_KEY", "docker_pass")
    mock_exec = mock.MagicMock(return_value=0)
    monkeypatch.setattr("envshield.cli.main.execute_docker_with_secrets", mock_exec)

    with pytest.raises(SystemExit) as exc:
        main(["docker", "--stealth", "--", "run", "secure_app"])
    assert exc.value.code == 0

    assert mock_exec.call_args[1]["stealth"] is True
