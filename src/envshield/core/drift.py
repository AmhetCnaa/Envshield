from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from envshield.core.profiles import list_profiles, parse_secrets_with_profile
from envshield.core.vault import unseal_raw_payload

# Common regex patterns to detect environment variable references across languages
ENV_PATTERNS = [
    # Python: os.environ["VAR"], os.environ.get("VAR"), os.getenv("VAR")
    re.compile(r'os\.(?:environ(?:\[|\.get\()|getenv\()[\'"]([A-Z0-9_]{2,})[\'"]'),
    # JavaScript / TypeScript: process.env.VAR or process.env["VAR"]
    re.compile(r'process\.env(?:\.([A-Z0-9_]{2,})|\[[\'"]([A-Z0-9_]{2,})[\'"]\])'),
    # Go: os.Getenv("VAR"), os.LookupEnv("VAR")
    re.compile(r'os\.(?:Getenv|LookupEnv)\([\'"]([A-Z0-9_]{2,})[\'"]\)'),
    # Rust: std::env::var("VAR"), env::var("VAR")
    re.compile(r'(?:std::)?env::var\([\'"]([A-Z0-9_]{2,})[\'"]\)'),
    # Java / Kotlin: System.getenv("VAR")
    re.compile(r'System\.getenv\([\'"]([A-Z0-9_]{2,})[\'"]\)'),
    # Ruby: ENV["VAR"] or ENV.fetch("VAR")
    re.compile(r'ENV(?:\.fetch)?\[[\'"]([A-Z0-9_]{2,})[\'"]\]'),
    # Shell / Dockerfile / Compose: ${VAR} or $VAR
    re.compile(r'\$\{([A-Z0-9_]{2,})(?::-|\+|=)?[^}]*\}'),
]

IGNORE_DIRS = {
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
    ".idea",
    ".vscode",
}

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".sh",
    ".bash",
    ".env.example",
    "Dockerfile",
}


@dataclass
class DriftFinding:
    key: str
    category: str  # "MISSING_IN_VAULT", "DEAD_SECRET", "PROFILE_MISMATCH", "MISSING_IN_EXAMPLE"
    description: str
    occurrences: list[str] = field(default_factory=list)


@dataclass
class DriftReport:
    vault_path: str
    scanned_files_count: int
    detected_code_vars: dict[str, list[str]] = field(default_factory=dict)
    vault_keys: set[str] = field(default_factory=set)
    example_keys: set[str] = field(default_factory=set)
    findings: list[DriftFinding] = field(default_factory=list)

    def has_issues(self) -> bool:
        return any(f.category in ("MISSING_IN_VAULT", "PROFILE_MISMATCH") for f in self.findings)


def scan_codebase_env_vars(root_dir: Path | str) -> tuple[dict[str, list[str]], int]:
    """
    Scans repository source files to extract environment variables referenced in code.
    Returns a mapping of {VAR_NAME: [file:line, ...]} and the total file count.
    """
    root = Path(root_dir).resolve()
    var_locations: dict[str, list[str]] = {}
    file_count = 0

    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            file_path = Path(base) / file
            if file_path.suffix not in SOURCE_EXTENSIONS and file != "Dockerfile":
                continue

            file_count += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = file_path.relative_to(root)
            for line_no, line in enumerate(content.splitlines(), start=1):
                # Ignore comment lines
                stripped = line.strip()
                if stripped.startswith(("#", "//", "/*", "*")):
                    continue

                for pattern in ENV_PATTERNS:
                    for match in pattern.finditer(line):
                        # Extract first non-None capture group
                        var_name = next((g for g in match.groups() if g), None)
                        if var_name:
                            # Filter out false positives / common language keywords
                            if var_name in ("PATH", "HOME", "USER", "TERM", "SHELL", "PWD"):
                                continue
                            var_locations.setdefault(var_name, []).append(f"{rel_path}:{line_no}")

    return var_locations, file_count


def parse_example_file(example_path: Path | str) -> set[str]:
    """Extracts keys defined in a .env.example or template file."""
    p = Path(example_path)
    if not p.is_file():
        return set()

    keys: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k = line.split("=", 1)[0].strip()
            if k:
                keys.add(k)
    return keys


def detect_secret_drift(
    root_dir: Path | str,
    vault_path: Path | str,
    example_path: Path | str | None = None,
    password: str | None = None,
    identity: Path | str | None = None,
) -> DriftReport:
    """
    Analyzes secrets health and drift across the codebase, vault profiles, and .env.example.
    Zero disk leakage: vault is decrypted in RAM.
    """
    root = Path(root_dir).resolve()
    v_path = Path(vault_path)
    if not v_path.is_file():
        raise FileNotFoundError(f"Vault file not found: {v_path}")

    # 1. Unseal vault into memory
    plaintext, fmt = unseal_raw_payload(v_path, password=password, identity_path=identity)
    available_profiles = list_profiles(plaintext, format_type=fmt)

    profile_map: dict[str, dict[str, str]] = {}
    if available_profiles:
        for prof in available_profiles:
            profile_map[prof] = parse_secrets_with_profile(
                plaintext, profile=prof, format_type=fmt
            )
    else:
        profile_map["default"] = parse_secrets_with_profile(plaintext, None, format_type=fmt)

    # Union of all keys in the vault across all profiles
    all_vault_keys: set[str] = set()
    for prof_vars in profile_map.values():
        all_vault_keys.update(prof_vars.keys())

    # 2. Scan codebase for environment variables
    code_vars, files_scanned = scan_codebase_env_vars(root)

    # 3. Read .env.example if available
    ex_keys: set[str] = set()
    if example_path:
        ex_keys = parse_example_file(example_path)
    else:
        default_ex = root / ".env.example"
        if default_ex.is_file():
            ex_keys = parse_example_file(default_ex)

    report = DriftReport(
        vault_path=str(v_path),
        scanned_files_count=files_scanned,
        detected_code_vars=code_vars,
        vault_keys=all_vault_keys,
        example_keys=ex_keys,
    )

    # A. Check for variables used in code or documented in .env.example but missing in vault
    for var, locs in code_vars.items():
        if var not in all_vault_keys:
            report.findings.append(
                DriftFinding(
                    key=var,
                    category="MISSING_IN_VAULT",
                    description=f"Variable '{var}' is referenced in codebase but missing from encrypted vault.",
                    occurrences=locs[:5],
                )
            )

    for ex_key in ex_keys:
        if ex_key not in all_vault_keys and ex_key not in code_vars:
            report.findings.append(
                DriftFinding(
                    key=ex_key,
                    category="MISSING_IN_VAULT",
                    description=f"Variable '{ex_key}' is listed in .env.example but missing from encrypted vault.",
                )
            )

    # B. Check for dead / orphan secrets in vault that are never referenced
    for v_key in all_vault_keys:
        if v_key not in code_vars and v_key not in ex_keys:
            report.findings.append(
                DriftFinding(
                    key=v_key,
                    category="DEAD_SECRET",
                    description=f"Key '{v_key}' exists in vault but was not found in codebase or .env.example.",
                )
            )

    # C. Profile Mismatch: check discrepancies between profiles (e.g. development vs production)
    if "development" in profile_map and "production" in profile_map:
        dev_keys = set(profile_map["development"].keys())
        prod_keys = set(profile_map["production"].keys())

        missing_in_prod = dev_keys - prod_keys
        for k in missing_in_prod:
            report.findings.append(
                DriftFinding(
                    key=k,
                    category="PROFILE_MISMATCH",
                    description=f"Key '{k}' is defined in '[development]' profile but missing in '[production]'!",
                )
            )

    return report
