from __future__ import annotations

import subprocess
from typing import Any

from envshield.core.formats import (
    flatten_dict,
    parse_env_content,
)


class ProfileNotFoundError(KeyError):
    """Raised when the specified environment profile does not exist in the vault."""


def detect_git_branch_profile(default: str = "development") -> str:
    """
    Detects the current git branch and maps it to a standard profile name.
    - main / master -> production
    - staging / stage / test -> staging
    - dev / develop / feature/* -> development
    """
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0,
        )
        if res.returncode == 0:
            branch = res.stdout.strip().lower()
            if branch in ("main", "master", "production", "prod"):
                return "production"
            if branch in ("staging", "stage", "test", "testing"):
                return "staging"
            if branch in ("dev", "develop", "development") or "/" in branch:
                return "development"
    except Exception:
        pass
    return default


def list_profiles(content: str, format_type: str = "env") -> list[str]:
    """Returns a list of profile names found in the secret payload."""
    fmt = format_type.lower()
    if fmt == "env":
        profiles: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]") and not line.startswith("[#"):
                section = line[1:-1].strip()
                if section and section not in profiles:
                    profiles.append(section)
        return profiles

    # For structured JSON/TOML/YAML, check top-level dict keys
    try:
        data: dict[str, Any] = {}
        if fmt == "json":
            import json

            data = json.loads(content)
        elif fmt == "toml":
            import tomllib

            data = tomllib.loads(content)
        elif fmt in ("yaml", "yml"):
            try:
                import yaml

                data = yaml.safe_load(content)
            except ImportError:
                import json

                data = json.loads(content)

        if isinstance(data, dict):
            # If keys contain common environments, treat as profiled
            keys = [k for k, v in data.items() if isinstance(v, dict)]
            return keys
    except Exception:
        pass

    return []


def parse_profiled_env(content: str, profile: str | None = None) -> dict[str, str]:
    """
    Parses an INI/section-styled .env file:
    [default]
    APP=MyApp

    [development]
    DEBUG=true

    [production]
    DEBUG=false
    """
    lines = content.splitlines()
    sections: dict[str, list[str]] = {"default": []}
    current_section = "default"
    has_sections = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]") and not stripped.startswith("[#"):
            current_section = stripped[1:-1].strip()
            has_sections = True
            if current_section not in sections:
                sections[current_section] = []
        else:
            sections[current_section].append(line)

    # If no section headers were found, parse as flat standard .env
    if not has_sections:
        return parse_env_content(content)

    available_sections = [s for s in sections if s != "default"]

    if profile is None:
        # No profile requested: load default section, or if default is empty and only 1 profile exists, load it
        res = parse_env_content("\n".join(sections.get("default", [])))
        if not res and len(available_sections) == 1:
            return parse_env_content("\n".join(sections[available_sections[0]]))
        return res

    prof_key = profile.strip()
    # Check case-insensitive match
    matching_section: str | None = None
    for s in sections:
        if s.lower() == prof_key.lower():
            matching_section = s
            break

    if not matching_section:
        raise ProfileNotFoundError(
            f"Profile '{profile}' not found in vault. Available profiles: {', '.join(sections.keys())}"
        )

    # Merge: base 'default' + specific profile
    merged = parse_env_content("\n".join(sections.get("default", [])))
    specific = parse_env_content("\n".join(sections[matching_section]))
    merged.update(specific)
    return merged


def parse_secrets_with_profile(
    content: str,
    profile: str | None = None,
    format_type: str = "auto",
    path_hint: str = "",
) -> dict[str, str]:
    """
    Parses secrets content, selecting and merging the requested profile.
    Falls back gracefully to standard flat parsing if no profiles exist.
    """
    # If format is env or auto-detected as env
    if format_type in ("env", "auto") and any(
        line.strip().startswith("[") and line.strip().endswith("]") for line in content.splitlines()
    ):
        return parse_profiled_env(content, profile=profile)

    # For structured JSON / TOML / YAML with profile dictionaries
    if format_type in ("json", "toml", "yaml", "yml"):
        try:
            if format_type == "json":
                import json

                data = json.loads(content)
            elif format_type == "toml":
                import tomllib

                data = tomllib.loads(content)
            else:
                try:
                    import yaml

                    data = yaml.safe_load(content)
                except ImportError:
                    import json

                    data = json.loads(content)

            if isinstance(data, dict) and profile:
                # Check if profile exists as top-level dict key
                prof_data = data.get(profile) or data.get(profile.lower())
                default_data = data.get("default", {})
                if isinstance(prof_data, dict):
                    merged_dict = default_data.copy() if isinstance(default_data, dict) else {}
                    merged_dict.update(prof_data)
                    return flatten_dict(merged_dict)
        except Exception:
            pass

    from envshield.core.formats import parse_secrets

    return parse_secrets(content, format_type=format_type, path_hint=path_hint)
