from __future__ import annotations

import abc
import base64
import hashlib
import json
import os
import re
import struct
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from envshield.core.audit import record_audit_event
from envshield.core.memory import SecureBuffer


class KmsProviderError(Exception):
    """Raised when a KMS operation fails."""


class KmsProvider(abc.ABC):
    """Abstract base class for Cloud and Mock KMS providers."""

    name: str

    @abc.abstractmethod
    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        """Encrypts 32-byte DEK. Returns (ciphertext_b64, metadata_dict)."""

    @abc.abstractmethod
    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        """Decrypts ciphertext_b64 and returns the 32-byte DEK."""

    @abc.abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Checks whether the provider's SDK and credentials are configured."""


class MockKmsProvider(KmsProvider):
    """
    Mock / Deterministic In-Memory KMS Provider.
    Ideal for local testing, CI/CD sandbox runs, and offline verification.
    Key format: 'mock:<identifier>'
    """

    name = "mock"

    def _derive_mock_kek(self, key_id: str) -> bytes:
        seed = f"envshield-mock-master:{key_id}".encode()
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"envshield-mock-kms-salt",
            info=b"mock-kek",
        ).derive(seed)

    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        with SecureBuffer(self._derive_mock_kek(key_id)) as sec_kek:
            nonce = os.urandom(12)
            aesgcm = AESGCM(sec_kek.to_bytes())
            enc = aesgcm.encrypt(nonce, dek, None)
        envelope = {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "enc": base64.b64encode(enc).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("utf-8"), {}

    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        raw_env = json.loads(base64.b64decode(ciphertext_b64).decode("utf-8"))
        nonce = base64.b64decode(raw_env["nonce"])
        enc = base64.b64decode(raw_env["enc"])
        with SecureBuffer(self._derive_mock_kek(key_id)) as sec_kek:
            aesgcm = AESGCM(sec_kek.to_bytes())
            return aesgcm.decrypt(nonce, enc, None)


    def is_available(self) -> tuple[bool, str]:
        return True, "Mock KMS is always available"


class AwsKmsProvider(KmsProvider):
    """
    AWS KMS Provider.
    Supports ARNs ('arn:aws:kms:region:account:key/...'), aliases ('alias/name'),
    and uses boto3 or standard AWS IAM credentials / OIDC.
    """

    name = "aws"

    def _extract_region(self, key_id: str) -> str:
        m = re.match(r"^arn:aws:kms:([a-z0-9-]+):", key_id)
        if m:
            return m.group(1)
        return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

    def _get_boto3_client(self, region: str) -> Any:
        try:
            import boto3
        except ImportError as exc:
            raise KmsProviderError(
                "AWS KMS requires 'boto3'. Install it using: pip install 'envshield-cli[aws]' or pip install boto3"
            ) from exc
        return boto3.client("kms", region_name=region)

    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        region = self._extract_region(key_id)
        client = self._get_boto3_client(region)
        try:
            resp = client.encrypt(KeyId=key_id, Plaintext=dek)
            ciphertext = base64.b64encode(resp["CiphertextBlob"]).decode("utf-8")
            return ciphertext, {"region": region}
        except Exception as exc:
            raise KmsProviderError(f"AWS KMS encryption failed for {key_id}: {exc}") from exc

    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        region = metadata.get("region") or self._extract_region(key_id)
        client = self._get_boto3_client(region)
        try:
            blob = base64.b64decode(ciphertext_b64)
            resp = client.decrypt(CiphertextBlob=blob, KeyId=key_id)
            return resp["Plaintext"]
        except Exception as exc:
            raise KmsProviderError(f"AWS KMS decryption failed for {key_id}: {exc}") from exc

    def is_available(self) -> tuple[bool, str]:
        try:
            import boto3  # noqa: F401
        except ImportError:
            return False, "boto3 package is not installed"
        if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
            return True, "AWS credentials detected in environment"
        return True, "boto3 available (will attempt default credential provider chain)"


class GcpKmsProvider(KmsProvider):
    """
    Google Cloud KMS Provider.
    Key resource name format:
    'projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}'
    """

    name = "gcp"

    def _get_kms_client(self) -> Any:
        try:
            from google.cloud import kms
        except ImportError as exc:
            raise KmsProviderError(
                "GCP KMS requires 'google-cloud-kms'. Install it using: pip install 'envshield-cli[gcp]' or pip install google-cloud-kms"
            ) from exc
        return kms.KeyManagementServiceClient()

    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        client = self._get_kms_client()
        try:
            response = client.encrypt(request={"name": key_id, "plaintext": dek})
            ciphertext = base64.b64encode(response.ciphertext).decode("utf-8")
            return ciphertext, {"key_version": response.name}
        except Exception as exc:
            raise KmsProviderError(f"GCP KMS encryption failed for {key_id}: {exc}") from exc

    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        client = self._get_kms_client()
        try:
            raw_cipher = base64.b64decode(ciphertext_b64)
            response = client.decrypt(request={"name": key_id, "ciphertext": raw_cipher})
            return response.plaintext
        except Exception as exc:
            raise KmsProviderError(f"GCP KMS decryption failed for {key_id}: {exc}") from exc

    def is_available(self) -> tuple[bool, str]:
        try:
            from google.cloud import kms  # noqa: F401
        except ImportError:
            return False, "google-cloud-kms package is not installed"
        return True, "google-cloud-kms available"


class AzureKeyVaultProvider(KmsProvider):
    """
    Azure Key Vault Provider.
    Key URI: 'https://{vault-name}.vault.azure.net/keys/{key-name}'
    """

    name = "azure"

    def _get_crypto_client(self, key_id: str) -> Any:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as exc:
            raise KmsProviderError(
                "Azure Key Vault requires 'azure-keyvault-keys' & 'azure-identity'. "
                "Install using: pip install 'envshield-cli[azure]'"
            ) from exc
        return CryptographyClient(key_id, credential=DefaultAzureCredential())

    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        try:
            from azure.keyvault.keys.crypto import EncryptionAlgorithm

            client = self._get_crypto_client(key_id)
            result = client.encrypt(EncryptionAlgorithm.rsa_oaep_256, dek)
            ciphertext = base64.b64encode(result.ciphertext).decode("utf-8")
            return ciphertext, {"algorithm": "rsa_oaep_256"}
        except Exception as exc:
            raise KmsProviderError(f"Azure Key Vault encryption failed for {key_id}: {exc}") from exc

    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        try:
            from azure.keyvault.keys.crypto import EncryptionAlgorithm

            client = self._get_crypto_client(key_id)
            blob = base64.b64decode(ciphertext_b64)
            result = client.decrypt(EncryptionAlgorithm.rsa_oaep_256, blob)
            return result.plaintext
        except Exception as exc:
            raise KmsProviderError(f"Azure Key Vault decryption failed for {key_id}: {exc}") from exc

    def is_available(self) -> tuple[bool, str]:
        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401
            from azure.keyvault.keys.crypto import CryptographyClient  # noqa: F401
        except ImportError:
            return False, "azure-keyvault-keys / azure-identity not installed"
        return True, "Azure Key Vault SDK available"


class HashiCorpVaultProvider(KmsProvider):
    """
    HashiCorp Vault Transit Secrets Engine Provider.
    Uses zero-dependency HTTP REST API calls via 'requests'.
    Format: 'vault:transit/{key-name}' or 'vault:{key-name}'
    Environment: VAULT_ADDR (default: http://127.0.0.1:8200), VAULT_TOKEN
    """

    name = "vault"

    def _get_config(self) -> tuple[str, str]:
        import urllib.parse

        addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
        parsed = urllib.parse.urlparse(addr)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise KmsProviderError(f"Invalid VAULT_ADDR scheme or host: '{addr}'. Must be https:// or http://.")
        token = os.environ.get("VAULT_TOKEN", "")
        if not token:
            raise KmsProviderError("VAULT_TOKEN environment variable is required for HashiCorp Vault.")
        return addr, token


    def _clean_key(self, key_id: str) -> str:
        k = key_id
        if k.startswith("vault:transit/"):
            return k[len("vault:transit/") :]
        if k.startswith("vault:"):
            return k[len("vault:") :]
        return k

    def encrypt(self, dek: bytes, key_id: str) -> tuple[str, dict[str, Any]]:
        import requests

        addr, token = self._get_config()
        key_name = self._clean_key(key_id)
        url = f"{addr}/v1/transit/encrypt/{key_name}"
        headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        b64_plain = base64.b64encode(dek).decode("utf-8")

        try:
            resp = requests.post(url, headers=headers, json={"plaintext": b64_plain}, timeout=10)
            if resp.status_code != 200:
                raise KmsProviderError(f"Vault error ({resp.status_code}): {resp.text}")
            data = resp.json().get("data", {})
            ciphertext = data.get("ciphertext")
            if not ciphertext:
                raise KmsProviderError("Vault response missing ciphertext.")
            return base64.b64encode(ciphertext.encode("utf-8")).decode("utf-8"), {"vault_addr": addr}
        except Exception as exc:
            raise KmsProviderError(f"HashiCorp Vault encryption failed for {key_name}: {exc}") from exc

    def decrypt(self, ciphertext_b64: str, key_id: str, metadata: dict[str, Any]) -> bytes:
        import requests

        addr, token = self._get_config()
        key_name = self._clean_key(key_id)
        url = f"{addr}/v1/transit/decrypt/{key_name}"
        headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        raw_ciphertext = base64.b64decode(ciphertext_b64).decode("utf-8")

        try:
            resp = requests.post(url, headers=headers, json={"ciphertext": raw_ciphertext}, timeout=10)
            if resp.status_code != 200:
                raise KmsProviderError(f"Vault error ({resp.status_code}): {resp.text}")
            data = resp.json().get("data", {})
            b64_plain = data.get("plaintext")
            if not b64_plain:
                raise KmsProviderError("Vault response missing plaintext.")
            return base64.b64decode(b64_plain)
        except Exception as exc:
            raise KmsProviderError(f"HashiCorp Vault decryption failed for {key_name}: {exc}") from exc

    def is_available(self) -> tuple[bool, str]:
        token = os.environ.get("VAULT_TOKEN")
        if token:
            return True, f"VAULT_TOKEN detected (Addr: {os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')})"
        return False, "VAULT_TOKEN environment variable not set"


# Registry of available KMS providers
_PROVIDERS: dict[str, KmsProvider] = {
    "mock": MockKmsProvider(),
    "aws": AwsKmsProvider(),
    "gcp": GcpKmsProvider(),
    "azure": AzureKeyVaultProvider(),
    "vault": HashiCorpVaultProvider(),
}


def resolve_kms_provider(key_spec: str) -> tuple[KmsProvider, str]:
    """
    Parses a key identifier/ARN/URI and returns the appropriate (provider, normalized_key_id).
    Supports:
      - 'mock:<identifier>' or 'kms:mock:<identifier>' -> MockKmsProvider
      - 'arn:aws:kms:...' or 'aws:<arn/key>' or 'kms:aws:...' -> AwsKmsProvider
      - 'projects/.../cryptoKeys/...' or 'gcp:...' or 'kms:gcp:...' -> GcpKmsProvider
      - 'https://<vault>.vault.azure.net/keys/...' or 'azure:...' -> AzureKeyVaultProvider
      - 'vault:transit/...' or 'vault:...' or 'kms:vault:...' -> HashiCorpVaultProvider
    """
    cleaned = key_spec.strip()

    cleaned = cleaned.removeprefix("kms:")

    if cleaned.startswith("mock:"):
        return _PROVIDERS["mock"], cleaned[5:]

    if cleaned.startswith(("arn:aws:kms:", "aws:")):
        key_id = cleaned.removeprefix("aws:")
        return _PROVIDERS["aws"], key_id

    if cleaned.startswith(("projects/", "gcp:")):
        key_id = cleaned.removeprefix("gcp:")
        return _PROVIDERS["gcp"], key_id

    if ".vault.azure.net" in cleaned or cleaned.startswith("azure:"):
        key_id = cleaned.removeprefix("azure:")
        return _PROVIDERS["azure"], key_id

    if cleaned.startswith(("vault:", "transit/")):
        return _PROVIDERS["vault"], cleaned

    raise ValueError(
        f"Unable to determine KMS provider for '{key_spec}'. "
        "Prefix with provider name, e.g. 'aws:arn:aws:kms:...', 'gcp:projects/...', 'mock:test', or 'vault:transit/...'"
    )


def encrypt_dek_with_kms(dek: bytes, key_spec: str) -> dict[str, Any]:
    """
    Encrypts DEK using the specified KMS provider and returns a standard KMS slot dictionary.
    """
    provider, key_id = resolve_kms_provider(key_spec)
    ciphertext_b64, metadata = provider.encrypt(dek, key_id)
    fp = hashlib.sha256(f"{provider.name}:{key_id}".encode()).hexdigest()[:16]

    return {
        "type": "kms",
        "provider": provider.name,
        "key_id": key_id,
        "fingerprint": fp,
        "encrypted_dek": ciphertext_b64,
        "metadata": metadata,
    }


def decrypt_dek_with_kms(slot: dict[str, Any]) -> bytes | None:
    """
    Attempts to decrypt the DEK in a KMS slot using the provider.
    Returns bytes on success, or None if provider credentials are not available or operation fails.
    """
    provider_name = slot.get("provider")
    key_id = slot.get("key_id")
    ciphertext_b64 = slot.get("encrypted_dek")
    metadata = slot.get("metadata", {})

    if not provider_name or not key_id or not ciphertext_b64:
        return None

    provider = _PROVIDERS.get(provider_name)
    if not provider:
        return None

    try:
        return provider.decrypt(ciphertext_b64, key_id, metadata)
    except Exception:
        # Graceful fallback: do not crash if cloud credentials are not active on this host
        return None


def probe_kms_key(key_spec: str) -> tuple[bool, str]:
    """
    Performs an end-to-end encrypt and decrypt test probe to verify KMS permissions and connectivity.
    """
    probe = os.urandom(32)
    try:
        provider, key_id = resolve_kms_provider(key_spec)
        ciphertext, meta = provider.encrypt(probe, key_id)
        decrypted = provider.decrypt(ciphertext, key_id, meta)
        if decrypted == probe:
            return True, f"KMS key '{key_spec}' ({provider.name}) is fully operational."
        return False, "Decrypted probe does not match original plaintext."
    except Exception as exc:
        return False, str(exc)


def list_kms_slots(vault_path: Path | str) -> list[dict[str, Any]]:
    """
    Inspects a vault's header and returns all attached KMS recipient slots.
    """
    path = Path(vault_path)
    if not path.is_file():
        raise FileNotFoundError(f"Vault file not found: {path}")

    raw_bytes = path.read_bytes()
    from envshield.core.vault import V2_MAGIC

    if not raw_bytes.startswith(V2_MAGIC):
        return []

    header_len = struct.unpack(">I", raw_bytes[len(V2_MAGIC) : len(V2_MAGIC) + 4])[0]
    header_start = len(V2_MAGIC) + 4
    header_end = header_start + header_len
    header_json = json.loads(raw_bytes[header_start:header_end].decode("utf-8"))

    slots = header_json.get("slots", [])
    kms_slots = []
    for s in slots:
        if s.get("type") == "kms":
            provider_name = s.get("provider", "")
            key_id = s.get("key_id", "")
            provider = _PROVIDERS.get(provider_name)
            avail, status_msg = provider.is_available() if provider else (False, "Unknown provider")
            
            # Format canonical key_spec
            if key_id.startswith(("arn:aws:kms:", "projects/", "https://")):
                key_spec = key_id
            else:
                key_spec = f"{provider_name}:{key_id}"

            kms_slots.append(
                {
                    "provider": provider_name,
                    "key_id": key_id,
                    "key_spec": key_spec,
                    "fingerprint": s.get("fingerprint"),
                    "available": avail,
                    "status": status_msg,
                }
            )
    return kms_slots


def add_kms_to_vault(
    vault_path: Path | str,
    key_spec: str,
    password: str | None = None,
    identity: Path | str | None = None,
) -> None:
    """
    Decrypts an existing vault in RAM, preserves existing team/KMS recipients,
    adds the new KMS recipient slot, and re-seals it in place. Zero disk writes.
    """
    from envshield.core.recipients import Recipient
    from envshield.core.team import get_all_team_recipients
    from envshield.core.vault import seal_payload, unseal_raw_payload

    path = Path(vault_path)
    plaintext, fmt = unseal_raw_payload(path, password=password, identity_path=identity)

    existing_slots = list_kms_slots(path)
    existing_specs = [s["key_spec"] for s in existing_slots]
    provider, key_id = resolve_kms_provider(key_spec)

    all_specs = list(existing_specs)
    if key_spec not in all_specs and f"{provider.name}:{key_id}" not in all_specs:
        all_specs.append(key_spec)

    all_recipients: list[Recipient] = list(get_all_team_recipients(path.parent))
    for k in all_specs:
        all_recipients.append(Recipient.from_string(k))

    seal_payload(
        payload_content=plaintext,
        target_path=path,
        password=password,
        recipients=all_recipients,
        format_type=fmt,
    )

    record_audit_event(
        action="KMS_ADD",
        target_path=path,
        key_id=f"kms:{provider.name}:{key_id[:16]}",
        details={"key_spec": key_spec},
    )


def remove_kms_from_vault(
    vault_path: Path | str,
    key_spec: str,
    password: str | None = None,
    identity: Path | str | None = None,
) -> bool:
    """
    Removes a KMS key recipient from the vault and re-seals in RAM.
    """
    from envshield.core.recipients import Recipient
    from envshield.core.team import get_all_team_recipients
    from envshield.core.vault import seal_payload, unseal_raw_payload

    path = Path(vault_path)
    existing_slots = list_kms_slots(path)

    provider, target_key_id = resolve_kms_provider(key_spec)
    matching = [
        s
        for s in existing_slots
        if s["key_id"] == target_key_id
        or s["key_spec"] == key_spec
        or s["fingerprint"] == key_spec
    ]
    if not matching:
        return False

    plaintext, fmt = unseal_raw_payload(path, password=password, identity_path=identity)
    remaining_specs = [
        s["key_spec"]
        for s in existing_slots
        if s["key_id"] != target_key_id
        and s["key_spec"] != key_spec
        and s["fingerprint"] != key_spec
    ]

    all_recipients: list[Recipient] = list(get_all_team_recipients(path.parent))
    for k in remaining_specs:
        all_recipients.append(Recipient.from_string(k))

    if not all_recipients and not password:
        raise ValueError(
            "Cannot remove the only recipient when no master password is set on the vault."
        )

    seal_payload(
        payload_content=plaintext,
        target_path=path,
        password=password,
        recipients=all_recipients if all_recipients else None,
        format_type=fmt,
    )

    record_audit_event(
        action="KMS_REMOVE",
        target_path=path,
        key_id=f"kms:{provider.name}:{target_key_id[:16]}",
        details={"key_spec": key_spec},
    )
    return True


def generate_ci_workflow(provider: str = "github", kms_key: str | None = None) -> str:
    """
    Generates a production-ready CI/CD workflow configuration snippet for Envshield.
    """
    if provider == "gitlab":
        return f"""# .gitlab-ci.yml - Envshield CI Integration
test:
  stage: test
  image: python:3.11
  id_tokens:
    AWS_JWT:
      aud: https://gitlab.com
  before_script:
    - pip install envshield-cli[aws]
  script:
    - envshield run -- python -m pytest
  variables:
    AWS_REGION: "us-east-1"
    # KMS Key attached to vault: {kms_key or 'arn:aws:kms:...'}
"""

    return """# .github/workflows/envshield.yml
name: Test & Build with Envshield Secrets

on:
  push:
    branches: [main]
  pull_request:

permissions:
  id-token: write   # Required for AWS OIDC / GCP Workload Identity
  contents: read

jobs:
  run-with-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      # AWS OIDC Authentication (No permanent AWS credentials required in GitHub Secrets!)
      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsEnvshieldRole
          aws-region: us-east-1

      - name: Install Dependencies
        run: |
          pip install envshield-cli[aws]
          pip install -r requirements.txt

      # Envshield unseals vault DEK via KMS in memory and redacts all output
      - name: Run Tests with Zero-Disk Injected Secrets
        run: |
          envshield run -- python -m pytest
"""
