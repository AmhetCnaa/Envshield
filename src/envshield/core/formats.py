from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = None  # type: ignore


def flatten_dict(nested: dict[str, Any], prefix: str = "", sep: str = "__") -> dict[str, str]:
    """
    Recursively flattens nested dictionaries into single-level KEY_SUBKEY=VALUE strings.
    Example: {"database": {"port": 5432}} -> {"DATABASE__PORT": "5432"}
    """
    items: dict[str, str] = {}
    for key, value in nested.items():
        clean_key = str(key).upper().replace("-", "_")
        full_key = f"{prefix}{sep}{clean_key}" if prefix else clean_key
        if isinstance(value, dict):
            items.update(flatten_dict(value, prefix=full_key, sep=sep))
        elif isinstance(value, (list, tuple)):
            # Join scalar lists or serialize json
            if all(isinstance(x, (str, int, float, bool)) for x in value):
                items[full_key] = ",".join(str(x) for x in value)
            else:
                items[full_key] = json.dumps(value)
        elif value is None:
            items[full_key] = ""
        elif isinstance(value, bool):
            items[full_key] = "true" if value else "false"
        else:
            items[full_key] = str(value)
    return items


def parse_env_content(content: str) -> dict[str, str]:
    """
    Parses standard KEY=VALUE environment strings strictly in memory.
    Supports comments, export prefix, and surrounding quotes.
    """
    env_vars: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            env_vars[key] = val
    return env_vars


def parse_json_content(content: str) -> dict[str, str]:
    """
    Parses JSON content and flattens it to environment variables.
    """
    data = json.loads(content)
    if isinstance(data, dict):
        return flatten_dict(data)
    raise ValueError("JSON secret payload must be an object/dictionary.")


def parse_toml_content(content: str) -> dict[str, str]:
    """
    Parses TOML content and flattens it to environment variables.
    """
    if tomllib is None:
        raise RuntimeError("TOML parsing requires Python 3.11+.")
    data = tomllib.loads(content)
    return flatten_dict(data)


def parse_yaml_content(content: str) -> dict[str, str]:
    """
    Parses YAML content. Uses PyYAML if available, or falls back to JSON compatibility.
    """
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(content)
        if isinstance(data, dict):
            return flatten_dict(data)
        raise ValueError("YAML secret payload must be an object/dictionary.")
    except ImportError:
        # Fallback: Many simple YAML files are JSON compatible
        try:
            return parse_json_content(content)
        except Exception as exc:
            raise RuntimeError(
                "PyYAML is not installed. Run `pip install pyyaml` to enable full YAML secret parsing."
            ) from exc


def detect_format(path: Path | str, content: str = "") -> str:
    """
    Detects secret file format based on file extension and/or content hints.
    Returns: 'env', 'json', 'toml', or 'yaml'.
    """
    suffix = Path(path).suffix.lower()
    name = Path(path).name.lower()

    if suffix in (".json",) or name.endswith(".json.enc"):
        return "json"
    if suffix in (".toml",) or name.endswith(".toml.enc"):
        return "toml"
    if suffix in (".yaml", ".yml") or name.endswith((".yaml.enc", ".yml.enc")):
        return "yaml"
    if suffix in (".env",) or ".env" in name:
        return "env"

    stripped = content.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return "json"
    if stripped.startswith("[") and "]" in stripped and "=" in stripped:
        return "toml"

    return "env"


def parse_secrets(content: str, format_type: str = "auto", path_hint: str = "") -> dict[str, str]:
    """
    Parses raw string content into an environment dictionary based on format.
    """
    fmt = detect_format(path_hint, content) if format_type == "auto" else format_type.lower()

    if fmt == "json":
        return parse_json_content(content)
    if fmt == "toml":
        return parse_toml_content(content)
    if fmt in ("yaml", "yml"):
        return parse_yaml_content(content)
    return parse_env_content(content)


def dump_secrets(secrets: dict[str, str], format_type: str = "env") -> str:
    """
    Serializes a dictionary of secrets into the requested format string.
    """
    fmt = format_type.lower()
    if fmt == "json":
        return json.dumps(secrets, indent=2)
    if fmt == "toml":
        lines = [f'{k} = "{v}"' for k, v in secrets.items()]
        return "\n".join(lines) + "\n"
    if fmt in ("yaml", "yml"):
        lines = [f"{k}: {json.dumps(v)}" for k, v in secrets.items()]
        return "\n".join(lines) + "\n"

    # Default .env format
    lines = [f"{k}={v}" for k, v in secrets.items()]
    return "\n".join(lines) + "\n"
