from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from envshield.core.recipients import Recipient
from envshield.core.vault import seal_payload, unseal_raw_payload

TEAM_CONFIG_DIR = ".envshield"
TEAM_CONFIG_FILE = "team.json"


def get_team_config_path(root_dir: Path | str | None = None) -> Path:
    """Returns the path to the team configuration file."""
    base = Path(root_dir or os.getcwd()).resolve()
    return base / TEAM_CONFIG_DIR / TEAM_CONFIG_FILE


def load_team_config(root_dir: Path | str | None = None) -> dict[str, Any]:
    """Loads team configuration from .envshield/team.json."""
    path = get_team_config_path(root_dir)
    if not path.is_file():
        return {
            "version": 1,
            "members": {},
            "vaults": [],
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": 1, "members": {}, "vaults": []}
        if "members" not in data or not isinstance(data["members"], dict):
            data["members"] = {}
        if "vaults" not in data or not isinstance(data["vaults"], list):
            data["vaults"] = []
        return data
    except Exception:
        return {"version": 1, "members": {}, "vaults": []}


def save_team_config(config: dict[str, Any], root_dir: Path | str | None = None) -> Path:
    """Saves team configuration to .envshield/team.json."""
    path = get_team_config_path(root_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def fetch_github_keys(username: str, timeout: float = 5.0) -> list[str]:
    """
    Fetches public OpenSSH keys for a GitHub user.
    Validates each key to ensure cryptographic compatibility.
    """
    clean_user = username.strip().lstrip("@")
    if not clean_user:
        raise ValueError("GitHub username cannot be empty.")

    url = f"https://github.com/{clean_user}.keys"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "EnvShield-CLI/0.4.0",
            "Accept": "text/plain",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError(f"GitHub user '{clean_user}' not found.") from exc
        raise RuntimeError(f"GitHub API error ({exc.code}): {exc.reason}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to connect to GitHub: {exc}") from exc

    valid_keys: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            # Validate that our Recipient class can parse and exchange with this key
            Recipient.from_string(line)
            valid_keys.append(line)
        except Exception:
            # Unsupported key type (e.g. DSA or non-standard curve), ignore
            pass

    if not valid_keys:
        raise ValueError(
            f"No compatible SSH public keys (Ed25519 or RSA) found on GitHub for user '{clean_user}'."
        )

    return valid_keys


def add_team_member(
    name: str,
    keys: list[str],
    source: str = "manual",
    root_dir: Path | str | None = None,
) -> dict[str, Any]:
    """
    Adds a team member with their public SSH keys to the team configuration.
    """
    config = load_team_config(root_dir)

    parsed_recipients: list[Recipient] = []
    for k in keys:
        try:
            parsed_recipients.append(Recipient.from_string(k))
        except Exception as exc:
            raise ValueError(f"Invalid public key for '{name}': {exc}") from exc

    member_data = {
        "name": name,
        "source": source,
        "keys": keys,
        "fingerprints": [r.fingerprint for r in parsed_recipients],
        "key_types": [r.key_type for r in parsed_recipients],
        "added_at": datetime.now(timezone.utc).isoformat(),
    }

    config["members"][name] = member_data
    save_team_config(config, root_dir)
    return member_data


def remove_team_member(name: str, root_dir: Path | str | None = None) -> bool:
    """Removes a member from the team configuration."""
    config = load_team_config(root_dir)
    if name in config["members"]:
        del config["members"][name]
        save_team_config(config, root_dir)
        return True
    return False


def list_team_members(root_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Returns a list of all team members."""
    config = load_team_config(root_dir)
    return list(config["members"].values())


def get_all_team_recipients(root_dir: Path | str | None = None) -> list[Recipient]:
    """Retrieves all public key recipients for all registered team members."""
    config = load_team_config(root_dir)
    recipients: list[Recipient] = []
    for member in config["members"].values():
        for k in member.get("keys", []):
            try:
                recipients.append(Recipient.from_string(k))
            except Exception:
                pass
    return recipients


def find_project_vaults(root_dir: Path | str | None = None) -> list[Path]:
    """
    Scans the repository to locate all encrypted .enc vault files.
    Ignores common non-project directories (.git, .venv, node_modules, dist, etc.).
    """
    base = Path(root_dir or os.getcwd()).resolve()
    ignored_dirs = {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
    }

    vaults: list[Path] = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
        for file in files:
            if file.endswith(".enc"):
                vaults.append(Path(root) / file)

    return sorted(vaults)


def sync_team_vaults(
    root_dir: Path | str | None = None,
    password: str | None = None,
    identity_path: str | Path | None = None,
    specific_vaults: list[Path] | None = None,
) -> list[dict[str, Any]]:
    """
    Re-seals repository vaults in RAM using the current team recipient list.
    Zero-disk writes: every vault is decrypted in RAM and re-encrypted directly.
    """
    recipients = get_all_team_recipients(root_dir)
    if not recipients and not password:
        raise ValueError(
            "Cannot sync vaults: No team members registered and no master password provided."
        )

    vaults = specific_vaults if specific_vaults is not None else find_project_vaults(root_dir)
    results: list[dict[str, Any]] = []

    for vault in vaults:
        try:
            # 1. Unseal in RAM
            content, fmt = unseal_raw_payload(vault, password=password, identity_path=identity_path)

            # 2. Re-seal with all team recipients + optional password
            seal_payload(
                payload_content=content,
                target_path=vault,
                password=password,
                recipients=recipients,
                format_type=fmt,
            )
            results.append(
                {
                    "vault": str(vault),
                    "success": True,
                    "recipients_count": len(recipients),
                    "format": fmt,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "vault": str(vault),
                    "success": False,
                    "error": str(exc),
                }
            )

    return results
