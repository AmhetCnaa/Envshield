import os

from envshield.core.models import Finding, Severity


def parse_env_file(content: str) -> dict[str, tuple[str, int]]:
    """Parses an env file and returns a dict mapping key to (value, line_number)."""
    env_vars = {}
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'").strip('"')
            env_vars[key] = (val, line_num)
    return env_vars


def infer_type(value: str) -> str:
    """Infers the basic type of an environment variable string."""
    if not value:
        return "empty"
    if value.lower() in ("true", "false", "1", "0", "yes", "no"):
        return "boolean"
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return "int"
    try:
        float(value)
        return "float"
    except ValueError:
        pass
    return "string"


class EnvValidator:
    """Validates .env files against .env.example files for drift and type mismatches."""

    def validate(
        self, env_path: str, env_content: str, example_path: str, example_content: str
    ) -> list[Finding]:
        findings = []
        env_vars = parse_env_file(env_content)
        example_vars = parse_env_file(example_content)

        # Check for missing variables
        for key, (example_val, example_line) in example_vars.items():
            if key not in env_vars:
                findings.append(
                    Finding(
                        file_path=env_path,
                        line_number=0,  # Missing from file
                        rule_id="MISSING_ENV_VAR",
                        description=f"Missing required environment variable '{key}' defined in {os.path.basename(example_path)}.",
                        severity=Severity.HIGH,
                        remediation=f"Add '{key}' to your {os.path.basename(env_path)} file.",
                    )
                )
            else:
                # Type validation
                env_val, env_line = env_vars[key]
                example_type = infer_type(example_val)
                env_type = infer_type(env_val)

                # Only warn if example type is specific (not just empty or generic string if we wanted to be strict,
                # but let's check strict type mismatch for int/boolean/float)
                if example_type in ("int", "float", "boolean") and env_type not in (
                    "empty",
                    example_type,
                ):
                    findings.append(
                        Finding(
                            file_path=env_path,
                            line_number=env_line,
                            rule_id="ENV_TYPE_MISMATCH",
                            description=f"Type mismatch for '{key}': expected {example_type} (from {os.path.basename(example_path)}), got {env_type}.",
                            severity=Severity.MEDIUM,
                            remediation=f"Update '{key}' to be of type {example_type}.",
                        )
                    )

        # Check for undocumented extraneous variables
        for key, (env_val, env_line) in env_vars.items():
            if key not in example_vars:
                findings.append(
                    Finding(
                        file_path=env_path,
                        line_number=env_line,
                        rule_id="EXTRANEOUS_ENV_VAR",
                        description=f"Undocumented variable '{key}' found. Not present in {os.path.basename(example_path)}.",
                        severity=Severity.LOW,
                        remediation=f"Add '{key}' to {os.path.basename(example_path)} or remove it from {os.path.basename(env_path)}.",
                    )
                )

        return findings
