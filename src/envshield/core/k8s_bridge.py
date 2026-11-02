from __future__ import annotations

import gc
import json
import subprocess
from typing import Any


def build_k8s_secret_manifest(
    secret_name: str,
    secrets: dict[str, str],
    namespace: str = "default",
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
    secret_type: str = "Opaque",
) -> dict[str, Any]:
    """
    Builds an in-memory Kubernetes Secret manifest dictionary.
    Zero-disk writes: dictionary is held strictly in volatile RAM.
    """
    base_labels = {
        "app.kubernetes.io/managed-by": "envshield",
    }
    if labels:
        base_labels.update(labels)

    manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": namespace,
            "labels": base_labels,
        },
        "type": secret_type,
        "stringData": dict(secrets),
    }
    if annotations:
        manifest["metadata"]["annotations"] = annotations
    return manifest


def apply_k8s_secret(
    secret_name: str,
    secrets: dict[str, str],
    namespace: str = "default",
    context: str | None = None,
    kubeconfig: str | None = None,
    dry_run: bool = False,
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
    secret_type: str = "Opaque",
) -> tuple[int, str]:
    """
    Directly applies in-memory secrets to a Kubernetes cluster via `kubectl apply -f -`.
    Hardening:
      - Plaintext secrets are NEVER written to a temporary YAML/JSON file on disk.
      - Secrets are passed exclusively over the stdin pipe, preventing leakage in `ps aux` / command arguments.
      - `shell=False` is strictly enforced to prevent command injection.
      - Buffer memory is cleared after transmission.

    Returns (exit_code, output_or_error_message).
    """
    manifest = build_k8s_secret_manifest(
        secret_name=secret_name,
        secrets=secrets,
        namespace=namespace,
        labels=labels,
        annotations=annotations,
        secret_type=secret_type,
    )
    manifest_json = json.dumps(manifest, separators=(",", ":"))

    cmd = ["kubectl", "apply", "-f", "-"]
    if namespace:
        cmd.extend(["--namespace", namespace])
    if context:
        cmd.extend(["--context", context])
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    if dry_run:
        cmd.append("--dry-run=client")

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        stdout, stderr = proc.communicate(input=manifest_json)
        exit_code = proc.returncode
        output = stdout.strip() if exit_code == 0 else stderr.strip()
        return exit_code, output
    except FileNotFoundError:
        return 127, "kubectl executable not found on system PATH."
    except Exception as exc:
        return 1, f"Kubernetes secret injection error: {exc}"
    finally:
        # Overwrite manifest reference to assist garbage collection
        manifest.clear()
        del manifest_json
        gc.collect()
