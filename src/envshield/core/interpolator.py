from __future__ import annotations

import os
import re

VAR_PATTERN = re.compile(r"(?<!\\)\$\{([a-zA-Z0-9_]+)(?::-([^}]*))?\}|(?<!\\)\$([a-zA-Z0-9_]+)")


class CircularDependencyError(ValueError):
    """Raised when environment variable interpolation contains circular references."""


def interpolate_value(
    val: str,
    context: dict[str, str],
    host_env: dict[str, str] | None = None,
    stack: list[str] | None = None,
) -> str:
    """
    Interpolates ${VAR}, ${VAR:-default}, and $VAR inside a single string.
    Checks for circular dependencies using an evaluation stack.
    """
    if not val or ("$" not in val):
        return val.replace(r"\$", "$")

    if host_env is None:
        host_env = os.environ

    if stack is None:
        stack = []

    def _replace(match: re.Match[str]) -> str:
        var_braced = match.group(1)
        default_val = match.group(2)
        var_bare = match.group(3)

        var_name = var_braced or var_bare
        if not var_name:
            return match.group(0)

        if var_name in stack:
            chain = " -> ".join(stack + [var_name])
            raise CircularDependencyError(f"Circular dependency detected in interpolation: {chain}")

        # Check internal context first, then host environment
        if var_name in context:
            resolved_raw = context[var_name]
            resolved = interpolate_value(
                resolved_raw, context, host_env=host_env, stack=stack + [var_name]
            )
            # If resolved is non-empty, use it
            if resolved:
                return resolved
            # If empty and default provided, use default
            if default_val is not None:
                return default_val
            return ""

        if var_name in host_env:
            return host_env[var_name]

        if default_val is not None:
            return default_val

        return ""

    result = VAR_PATTERN.sub(_replace, val)
    return result.replace(r"\$", "$")


def interpolate_secrets(
    raw_secrets: dict[str, str],
    host_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Resolves all dynamic references (${VAR}, ${VAR:-default}) across the entire secrets dictionary.
    Zero disk touch: all substitutions happen purely in RAM.
    """
    resolved: dict[str, str] = {}
    for key, val in raw_secrets.items():
        resolved[key] = interpolate_value(val, raw_secrets, host_env=host_env, stack=[key])
    return resolved
