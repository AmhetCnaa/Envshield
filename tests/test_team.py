from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from envshield.cli.main import main
from envshield.core.team import (
    add_team_member,
    fetch_github_keys,
    list_team_members,
    remove_team_member,
    sync_team_vaults,
)
from envshield.core.vault import InvalidKey, seal_file, unseal_to_memory


def my_exit(code=0):
    raise SystemExit(code)


def generate_ed25519_key_pair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_ssh = (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        .decode("utf-8")
    )
    return priv, pub_ssh


def test_fetch_github_keys_success() -> None:
    _, pub_key_1 = generate_ed25519_key_pair()
    _, pub_key_2 = generate_ed25519_key_pair()
    mock_keys_response = f"{pub_key_1}\n{pub_key_2}\n# Comment line\n"

    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = mock_keys_response.encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with mock.patch("urllib.request.urlopen", return_value=mock_resp):
        keys = fetch_github_keys("ahmet")
        assert len(keys) == 2
        assert pub_key_1 in keys
        assert pub_key_2 in keys


def test_fetch_github_keys_not_found() -> None:
    http_err = urllib.error.HTTPError("http://example.com", 404, "Not Found", None, None)
    with mock.patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(ValueError, match="not found"):
            fetch_github_keys("nonexistent_user_999")


def test_team_lifecycle_and_re_seal_sync(tmp_path: Path) -> None:
    priv1, pub1 = generate_ed25519_key_pair()
    priv2, pub2 = generate_ed25519_key_pair()

    priv1_file = tmp_path / "priv1"
    priv1_file.write_bytes(
        priv1.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    priv2_file = tmp_path / "priv2"
    priv2_file.write_bytes(
        priv2.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    # 1. Start with member1 only
    add_team_member("alice", [pub1], source="manual", root_dir=tmp_path)
    members = list_team_members(root_dir=tmp_path)
    assert len(members) == 1
    assert members[0]["name"] == "alice"

    # Create an initial vault sealed for alice
    env_file = tmp_path / ".env"
    env_file.write_text("DB_PASS=super_confidential\nAPI_KEY=xyz123\n", encoding="utf-8")
    vault_file = tmp_path / ".env.enc"
    seal_file(env_file, vault_file, recipients=[pub1])

    # Alice can decrypt
    sec_alice = unseal_to_memory(vault_file, identity_path=priv1_file)
    assert sec_alice["DB_PASS"] == "super_confidential"

    # Bob cannot decrypt yet
    with pytest.raises(InvalidKey):
        unseal_to_memory(vault_file, identity_path=priv2_file)

    # 2. Onboard Bob (simulate adding Bob via team add)
    add_team_member("bob", [pub2], source="github:bob", root_dir=tmp_path)
    assert len(list_team_members(root_dir=tmp_path)) == 2

    # Sync / Re-seal repository vaults (authorized using Alice's key)
    results = sync_team_vaults(root_dir=tmp_path, identity_path=priv1_file)
    assert len(results) == 1
    assert results[0]["success"] is True
    assert results[0]["recipients_count"] == 2

    # Now BOTH Alice and Bob can decrypt!
    sec_bob = unseal_to_memory(vault_file, identity_path=priv2_file)
    assert sec_bob["DB_PASS"] == "super_confidential"
    assert sec_bob["API_KEY"] == "xyz123"

    # 3. Offboard Bob (simulate revoke access)
    removed = remove_team_member("bob", root_dir=tmp_path)
    assert removed is True
    assert len(list_team_members(root_dir=tmp_path)) == 1

    # Sync / Re-seal again
    sync_team_vaults(root_dir=tmp_path, identity_path=priv1_file)

    # Bob is now REVOKED and CANNOT decrypt!
    with pytest.raises(InvalidKey):
        unseal_to_memory(vault_file, identity_path=priv2_file)

    # Alice can still decrypt cleanly
    sec_alice_after = unseal_to_memory(vault_file, identity_path=priv1_file)
    assert sec_alice_after["DB_PASS"] == "super_confidential"


@mock.patch("sys.exit", side_effect=my_exit)
def test_cli_team_commands(mock_exit, tmp_path: Path, monkeypatch, capfd):
    monkeypatch.chdir(tmp_path)
    _, pub = generate_ed25519_key_pair()

    # 1. Team list (empty)
    with pytest.raises(SystemExit) as exc:
        main(["team", "list"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "No team members configured" in out

    # 2. Team add with --github (mocked)
    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = f"{pub}\n".encode()
    mock_resp.__enter__.return_value = mock_resp

    with mock.patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(SystemExit) as exc:
            main(["team", "add", "ahmet", "--github", "--no-sync"])
        assert exc.value.code == 0
        out, _ = capfd.readouterr()
        assert "Added team member 'ahmet'" in out

    # 3. Team list (now has ahmet)
    with pytest.raises(SystemExit) as exc:
        main(["team", "list"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "ahmet" in out
    assert "github:ahmet" in out

    # 4. Team remove
    with pytest.raises(SystemExit) as exc:
        main(["team", "remove", "ahmet", "--no-sync"])
    assert exc.value.code == 0
    out, _ = capfd.readouterr()
    assert "Removed team member 'ahmet'" in out
