from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_AUDIT_FILE = ".envshield.audit.jsonl"


def _canonical_json(data: dict[str, Any]) -> str:
    """Produces deterministic, canonically sorted JSON without whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_file_hash(path: Path | str) -> str:
    """Computes SHA-256 hex digest of a file if it exists."""
    p = Path(path)
    if not p.is_file():
        return ""
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_key_fingerprint(key_or_salt: bytes | str) -> str:
    """Computes a non-reversible SHA-256 fingerprint for audit identification."""
    if isinstance(key_or_salt, str):
        b = key_or_salt.encode("utf-8")
    else:
        b = key_or_salt
    return hashlib.sha256(b).hexdigest()[:16]


def get_audit_path(custom_path: Path | str | None = None) -> Path:
    """Resolves the audit file location."""
    if custom_path:
        return Path(custom_path)
    if os.environ.get("ENVSHIELD_AUDIT_FILE"):
        return Path(os.environ["ENVSHIELD_AUDIT_FILE"])
    return Path(DEFAULT_AUDIT_FILE)


def read_audit_entries(audit_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Reads all audit entries from the log file."""
    path = get_audit_path(audit_path)
    if not path.is_file():
        return []

    entries: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def record_audit_event(
    action: str,
    target_path: Path | str,
    key_id: str = "",
    details: dict[str, Any] | None = None,
    audit_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Appends a cryptographically chained entry to the tamper-evident audit log.
    Every entry includes the SHA-256 hash of the previous entry.
    """
    path = get_audit_path(audit_path)
    entries = read_audit_entries(path)

    prev_hash = "0" * 64
    next_index = 0
    if entries:
        last = entries[-1]
        next_index = int(last.get("index", len(entries) - 1)) + 1
        prev_hash = last.get("entry_hash", "0" * 64)

    timestamp = datetime.now(timezone.utc).isoformat()
    user = getpass.getuser()
    hostname = platform.node()
    file_sha256 = compute_file_hash(target_path)

    entry_data: dict[str, Any] = {
        "index": next_index,
        "timestamp": timestamp,
        "action": action.upper(),
        "user": user,
        "hostname": hostname,
        "target_file": str(target_path),
        "target_sha256": file_sha256,
        "key_fingerprint": key_id or "unspecified",
        "details": details or {},
        "prev_hash": prev_hash,
    }

    # Compute entry_hash over all fields
    canonical = _canonical_json(entry_data)
    entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    entry_data["entry_hash"] = entry_hash

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry_data) + "\n")

    return entry_data


def verify_audit_chain(audit_path: Path | str | None = None) -> tuple[bool, str]:
    """
    Verifies that the entire audit chain is structurally valid and untampered.
    Detects any modification, insertion, or deletion of log entries.
    """
    path = get_audit_path(audit_path)
    if not path.is_file():
        return True, "No audit log found. Chain is empty."

    entries = read_audit_entries(path)
    if not entries:
        return True, "Audit log is empty."

    expected_prev = "0" * 64
    for i, entry in enumerate(entries):
        actual_index = entry.get("index")
        if actual_index != i:
            return (
                False,
                f"Audit index discrepancy at entry #{i}: expected {i}, got {actual_index}.",
            )

        actual_prev = entry.get("prev_hash")
        if actual_prev != expected_prev:
            return (
                False,
                f"Tampering detected at entry #{i}: prev_hash mismatch. Chain has been altered.",
            )

        recorded_hash = entry.get("entry_hash")
        # Reconstruct canonical entry without entry_hash
        calc_dict = {k: v for k, v in entry.items() if k != "entry_hash"}
        calc_hash = hashlib.sha256(_canonical_json(calc_dict).encode("utf-8")).hexdigest()

        if calc_hash != recorded_hash:
            return (
                False,
                f"Tampering detected at entry #{i}: entry_hash mismatch. Payload has been modified.",
            )

        expected_prev = recorded_hash

    return True, f"Audit chain verified successfully ({len(entries)} valid tamper-evident entries)."
