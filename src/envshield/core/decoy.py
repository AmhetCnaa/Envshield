from __future__ import annotations

import json
import os
import platform
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from envshield.core.audit import record_audit_event


def generate_default_canary_secrets() -> dict[str, str]:
    """Generates realistic, completely inert decoy/canary environment secrets."""
    return {
        "ENV": "sandbox",
        "DEBUG": "true",
        "DATABASE_URL": "postgresql://decoy_guest:decoy_pass_trap@127.0.0.1:5432/decoy_sandbox",
        "API_KEY": "sk_canary_trap_9019283019283019283",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "STRIPE_SECRET_KEY": "sk_test_51MzTrapFakeTokenDoNotUse0000000",
        "HONEYPOT_ACTIVE": "true",
    }


def load_decoy_secrets(decoy_file: Path | str | None = None) -> dict[str, str]:
    """Loads custom decoy secrets from a file or falls back to synthetic canary secrets."""
    if decoy_file:
        p = Path(decoy_file)
        if p.is_file():
            from envshield.core.formats import parse_secrets

            return parse_secrets(p.read_text(encoding="utf-8"), path_hint=str(p))
    return generate_default_canary_secrets()


def _send_webhook_worker(webhook_url: str, payload: dict[str, Any]) -> None:
    """Delivers canary alert webhook in background without blocking CLI execution."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "EnvShield-Canary-Sentinel/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            _ = resp.read()
    except Exception:
        # Silent failure for stealthiness
        pass


def trigger_canary_alert(
    target_path: Path | str,
    webhook_url: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Records an immutable audit event and asynchronously dispatches a canary alert
    when an unauthorized decryption attempt or decoy trigger happens.
    """
    record_audit_event(
        action="DECOY_TRIGGERED",
        target_path=target_path,
        key_id="unauthorized_canary",
        details=details or {},
    )

    resolved_webhook = webhook_url or os.environ.get("ENVSHIELD_ALERT_WEBHOOK")
    if resolved_webhook:
        payload = {
            "event": "ENVSHIELD_CANARY_ALERT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": str(target_path),
            "hostname": platform.node(),
            "details": details or {},
        }
        thread = threading.Thread(
            target=_send_webhook_worker,
            args=(resolved_webhook, payload),
            daemon=True,
        )
        thread.start()
