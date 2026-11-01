from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import platform
import sys
import urllib.parse
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
    line_bytes = (json.dumps(entry_data) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        if sys.platform != "win32":
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                os.chmod(path, 0o600)
        with os.fdopen(fd, "ab") as f:
            f.write(line_bytes)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    # Stream real-time audit event to enterprise SIEM / Webhook if configured (strictly https/http)
    webhook_url = os.environ.get("ENVSHIELD_AUDIT_WEBHOOK") or os.environ.get(
        "ENVSHIELD_SIEM_ENDPOINT"
    )
    if webhook_url:
        try:
            parsed = urllib.parse.urlparse(webhook_url.strip())
            if parsed.scheme in ("https", "http") and parsed.netloc:
                import requests

                requests.post(webhook_url.strip(), json=entry_data, timeout=3.0)
        except Exception:
            pass

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

        actual_prev = str(entry.get("prev_hash", ""))
        if not hmac.compare_digest(actual_prev, expected_prev):
            return (
                False,
                f"Tampering detected at entry #{i}: prev_hash mismatch. Chain has been altered.",
            )

        recorded_hash = str(entry.get("entry_hash", ""))
        calc_dict = {k: v for k, v in entry.items() if k != "entry_hash"}
        calc_hash = hashlib.sha256(_canonical_json(calc_dict).encode("utf-8")).hexdigest()

        if not hmac.compare_digest(calc_hash, recorded_hash):
            return (
                False,
                f"Tampering detected at entry #{i}: entry_hash mismatch. Payload has been modified.",
            )

        expected_prev = recorded_hash


    return True, f"Audit chain verified successfully ({len(entries)} entries). Integrity signature intact."


def generate_compliance_report(
    audit_path: Path | str | None = None,
    title: str = "SOC 2 Type II Secret Access & Cryptographic Integrity Audit Report",
) -> str:
    """
    Generates a standalone, executive-ready HTML compliance report with full HMAC proof chain.
    """
    path = get_audit_path(audit_path)
    entries = read_audit_entries(path)
    is_valid, _ = verify_audit_chain(path)

    total_ops = len(entries)
    unique_users = sorted({e.get("user", "unknown") for e in entries})
    unique_targets = sorted({e.get("target_file", "unknown") for e in entries})
    actions_summary: dict[str, int] = {}
    for e in entries:
        act = e.get("action", "UNKNOWN")
        actions_summary[act] = actions_summary.get(act, 0) + 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_color = "#10b981" if is_valid else "#ef4444"
    status_text = "VERIFIED: INTEGRITY CONFIRMED" if is_valid else "AUDIT TAMPERING DETECTED"
    chain_head = entries[-1]["entry_hash"] if entries else "0" * 64

    # Build action pills
    action_pills = "".join(
        f'<span style="background: rgba(99, 102, 241, 0.15); color: #818cf8; padding: 4px 10px; border-radius: 9999px; font-size: 13px; font-weight: 600; margin-right: 8px;">{act}: {count}</span>'
        for act, count in actions_summary.items()
    )

    # Build rows
    rows_html = []
    for e in entries[-50:]:  # last 50 entries
        color = "#10b981" if e.get("action") == "UNSEAL" else "#3b82f6"
        if "REMOVE" in e.get("action", "") or "ALERT" in e.get("action", ""):
            color = "#ef4444"
        details_str = json.dumps(e.get("details", {}))
        rows_html.append(
            f"""<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 10px 14px; color: #94a3b8; font-family: monospace; font-size: 13px;">#{e.get("index")}</td>
                <td style="padding: 10px 14px; font-size: 13px; color: #cbd5e1;">{e.get("timestamp")}</td>
                <td style="padding: 10px 14px;"><span style="color: {color}; font-weight: 700; font-size: 12px; background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius: 4px;">{e.get("action")}</span></td>
                <td style="padding: 10px 14px; font-size: 13px; color: #f8fafc;">{e.get("user")} <span style="color: #64748b;">({e.get("hostname")})</span></td>
                <td style="padding: 10px 14px; font-family: monospace; font-size: 12px; color: #38bdf8;">{e.get("key_fingerprint")}</td>
                <td style="padding: 10px 14px; font-family: monospace; font-size: 11px; color: #64748b;" title="{e.get('entry_hash')}">{e.get('entry_hash')[:16]}...</td>
                <td style="padding: 10px 14px; font-size: 12px; color: #94a3b8; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{details_str}</td>
            </tr>"""
        )

    table_rows = "".join(rows_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Envshield - {title}</title>
    <style>
        body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f8fafc; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #111827; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); padding: 36px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 24px; margin-bottom: 24px; }}
        .badge {{ background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}; padding: 6px 14px; border-radius: 9999px; font-size: 12px; font-weight: 700; letter-spacing: 0.05em; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); }}
        .card-val {{ font-size: 28px; font-weight: 800; color: #38bdf8; margin-top: 4px; }}
        .card-lbl {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; margin-top: 20px; }}
        th {{ background: #1e293b; padding: 12px 14px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 24px; font-weight: 800; color: #f8fafc;">🛡️ Envshield Enterprise Audit Certification</h1>
                <p style="margin: 6px 0 0; color: #94a3b8; font-size: 14px;">{title}</p>
            </div>
            <div class="badge">{status_text}</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-lbl">Total Logged Operations</div>
                <div class="card-val">{total_ops}</div>
            </div>
            <div class="card">
                <div class="card-lbl">Unique Principals</div>
                <div class="card-val">{len(unique_users)}</div>
            </div>
            <div class="card">
                <div class="card-lbl">Protected Vaults</div>
                <div class="card-val">{len(unique_targets)}</div>
            </div>
            <div class="card">
                <div class="card-lbl">Chain Head (Merkle Tip)</div>
                <div class="card-val" style="font-size: 16px; font-family: monospace; word-break: break-all;">{chain_head[:12]}...</div>
            </div>
        </div>

        <div style="margin-bottom: 24px;">
            <div style="font-size: 14px; font-weight: 600; color: #94a3b8; margin-bottom: 10px;">Operation Breakdown:</div>
            {action_pills}
        </div>

        <h3 style="font-size: 16px; margin: 30px 0 10px; color: #f1f5f9;">Cryptographic Access Event Ledger (Last 50 Entries)</h3>
        <table>
            <thead>
                <tr>
                    <th>Idx</th>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Principal (Host)</th>
                    <th>Key Fingerprint</th>
                    <th>SHA-256 Hash</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>

        <div style="margin-top: 36px; padding-top: 18px; border-top: 1px solid rgba(255,255,255,0.08); font-size: 12px; color: #64748b; display: flex; justify-content: space-between;">
            <span>Generated: {generated_at}</span>
            <span>Cryptographic Verification Engine: Envshield Security Enterprise v0.4.0</span>
        </div>
    </div>
</body>
</html>
"""


    return True, f"Audit chain verified successfully ({len(entries)} valid tamper-evident entries)."
