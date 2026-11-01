from __future__ import annotations

import json
from pathlib import Path

from envshield.core.audit import read_audit_entries, record_audit_event, verify_audit_chain


def test_audit_record_and_verify(tmp_path: Path) -> None:
    audit_file = tmp_path / "test.audit.jsonl"

    record_audit_event("SEAL", tmp_path / ".env", key_id="key_1", audit_path=audit_file)
    record_audit_event(
        "RUN",
        tmp_path / ".env.enc",
        key_id="key_1",
        details={"command": ["app"]},
        audit_path=audit_file,
    )
    record_audit_event("EDIT", tmp_path / ".env.enc", key_id="key_1", audit_path=audit_file)

    entries = read_audit_entries(audit_file)
    assert len(entries) == 3
    assert entries[0]["index"] == 0
    assert entries[1]["index"] == 1
    assert entries[2]["index"] == 2
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    valid, msg = verify_audit_chain(audit_file)
    assert valid is True
    assert "Audit chain verified successfully" in msg


def test_audit_tampering_content_modified(tmp_path: Path) -> None:
    audit_file = tmp_path / "test.audit.jsonl"
    record_audit_event("SEAL", tmp_path / ".env", key_id="key_1", audit_path=audit_file)
    record_audit_event("RUN", tmp_path / ".env.enc", key_id="key_1", audit_path=audit_file)

    # Tamper with entry 0
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    data = json.loads(lines[0])
    data["action"] = "HACKED_ACTION"
    lines[0] = json.dumps(data)
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    valid, msg = verify_audit_chain(audit_file)
    assert valid is False
    assert "Tampering detected at entry #0" in msg


def test_audit_tampering_entry_deleted(tmp_path: Path) -> None:
    audit_file = tmp_path / "test.audit.jsonl"
    record_audit_event("SEAL", tmp_path / ".env", key_id="key_1", audit_path=audit_file)
    record_audit_event("RUN", tmp_path / ".env.enc", key_id="key_1", audit_path=audit_file)
    record_audit_event("EDIT", tmp_path / ".env.enc", key_id="key_1", audit_path=audit_file)

    # Delete entry 1
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    del lines[1]
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    valid, msg = verify_audit_chain(audit_file)
    assert valid is False
    assert "discrepancy" in msg or "Tampering" in msg
