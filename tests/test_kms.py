from __future__ import annotations

import base64
import os
from pathlib import Path
from unittest import mock

import pytest

from envshield.cli.main import main
from envshield.core.kms import (
    AwsKmsProvider,
    AzureKeyVaultProvider,
    GcpKmsProvider,
    HashiCorpVaultProvider,
    KmsProviderError,
    MockKmsProvider,
    add_kms_to_vault,
    decrypt_dek_with_kms,
    encrypt_dek_with_kms,
    generate_ci_workflow,
    list_kms_slots,
    probe_kms_key,
    remove_kms_from_vault,
    resolve_kms_provider,
)
from envshield.core.recipients import Recipient
from envshield.core.vault import seal_file, unseal_raw_payload, unseal_to_memory


def test_mock_kms_roundtrip() -> None:
    provider = MockKmsProvider()
    dek = os.urandom(32)
    key_id = "test-encryption-key"

    ciphertext_b64, meta = provider.encrypt(dek, key_id)
    assert isinstance(ciphertext_b64, str)
    assert meta == {}

    decrypted = provider.decrypt(ciphertext_b64, key_id, meta)
    assert decrypted == dek


def test_mock_kms_availability_and_probe() -> None:
    provider = MockKmsProvider()
    avail, msg = provider.is_available()
    assert avail is True
    assert "Mock KMS" in msg

    ok, probe_msg = probe_kms_key("mock:developer-test-key")
    assert ok is True
    assert "fully operational" in probe_msg


def test_resolve_kms_providers() -> None:
    # Mock
    p, k = resolve_kms_provider("mock:seed-123")
    assert isinstance(p, MockKmsProvider)
    assert k == "seed-123"

    p, k = resolve_kms_provider("kms:mock:seed-456")
    assert isinstance(p, MockKmsProvider)
    assert k == "seed-456"

    # AWS
    p, k = resolve_kms_provider("arn:aws:kms:eu-west-1:123456789012:key/abc-123")
    assert isinstance(p, AwsKmsProvider)
    assert k == "arn:aws:kms:eu-west-1:123456789012:key/abc-123"

    p, k = resolve_kms_provider("aws:alias/my-app-key")
    assert isinstance(p, AwsKmsProvider)
    assert k == "alias/my-app-key"

    # GCP
    p, k = resolve_kms_provider("projects/my-prj/locations/global/keyRings/kr/cryptoKeys/ck")
    assert isinstance(p, GcpKmsProvider)
    assert "cryptoKeys/ck" in k

    # Azure
    p, k = resolve_kms_provider("https://myvault.vault.azure.net/keys/mykey")
    assert isinstance(p, AzureKeyVaultProvider)
    assert "https://" in k

    # HashiCorp Vault
    p, k = resolve_kms_provider("vault:transit/payment-dek")
    assert isinstance(p, HashiCorpVaultProvider)
    assert "transit/payment-dek" in k

    # Invalid
    with pytest.raises(ValueError, match="Unable to determine KMS provider"):
        resolve_kms_provider("unknown-scheme:some-key")


def test_encrypt_and_decrypt_dek_slot() -> None:
    dek = os.urandom(32)
    slot = encrypt_dek_with_kms(dek, "mock:ci-runner-v1")
    assert slot["type"] == "kms"
    assert slot["provider"] == "mock"
    assert slot["key_id"] == "ci-runner-v1"

    recovered_dek = decrypt_dek_with_kms(slot)
    assert recovered_dek == dek

    # Tampered ciphertext
    corrupt_slot = dict(slot)
    corrupt_slot["encrypted_dek"] = base64.b64encode(b"invalid-corrupt-data").decode("utf-8")
    assert decrypt_dek_with_kms(corrupt_slot) is None


def test_vault_seal_and_unseal_pure_kms(tmp_path: Path) -> None:
    secret_env = tmp_path / ".env"
    secret_env.write_text("STRIPE_API_KEY=sk_live_pure_kms_token\nPORT=8080\n", encoding="utf-8")
    vault_path = tmp_path / ".env.enc"

    # Seal using only a KMS recipient (no password)
    kms_rec = Recipient.from_string("mock:cloud-runner-key")
    seal_file(
        source_path=secret_env,
        target_path=vault_path,
        password=None,
        recipients=[kms_rec],
    )

    # Unseal with no password and no SSH identity
    plaintext, fmt = unseal_raw_payload(vault_path)
    assert "STRIPE_API_KEY=sk_live_pure_kms_token" in plaintext
    assert fmt == "env"

    secrets = unseal_to_memory(vault_path)
    assert secrets["STRIPE_API_KEY"] == "sk_live_pure_kms_token"
    assert secrets["PORT"] == "8080"


def test_vault_hybrid_ssh_and_kms(tmp_path: Path) -> None:
    secret_env = tmp_path / ".env"
    secret_env.write_text("DATABASE_URL=postgres://user:pass@db:5432/main\n", encoding="utf-8")
    vault_path = tmp_path / ".env.enc"

    # Create dummy Ed25519 SSH keypair
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_openssh = pub.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    priv_file = tmp_path / "id_ed25519"
    priv_file.write_bytes(priv_pem)

    ssh_rec = Recipient.from_string(pub_openssh)
    kms_rec = Recipient.from_string("mock:ci-production-key")

    # Seal with BOTH developer SSH key and CI Cloud KMS key
    seal_file(
        source_path=secret_env,
        target_path=vault_path,
        password=None,
        recipients=[ssh_rec, kms_rec],
    )

    # Scenario 1: Developer on laptop with private key unlocks via SSH slot
    txt_dev, _ = unseal_raw_payload(vault_path, identity_path=priv_file)
    assert "DATABASE_URL=postgres" in txt_dev

    # Scenario 2: CI runner with no private SSH key unlocks via KMS slot
    with mock.patch("envshield.core.vault.find_default_identities", return_value=[]):
        txt_ci, _ = unseal_raw_payload(vault_path, identity_path=None)
        assert "DATABASE_URL=postgres" in txt_ci


def test_kms_add_and_remove(tmp_path: Path) -> None:
    secret_env = tmp_path / ".env"
    secret_env.write_text("API_SECRET=super_secret_value\n", encoding="utf-8")
    vault_path = tmp_path / ".env.enc"

    # Initially seal with mock:key-1
    seal_file(
        source_path=secret_env,
        target_path=vault_path,
        password=None,
        recipients=[Recipient.from_string("mock:key-1")],
    )

    slots = list_kms_slots(vault_path)
    assert len(slots) == 1
    assert slots[0]["key_id"] == "key-1"

    # Add second KMS recipient mock:key-2
    add_kms_to_vault(vault_path, "mock:key-2")
    slots_after_add = list_kms_slots(vault_path)
    assert len(slots_after_add) == 2
    key_ids = [s["key_id"] for s in slots_after_add]
    assert "key-1" in key_ids
    assert "key-2" in key_ids

    # Unseal with mock:key-2 works
    txt, _ = unseal_raw_payload(vault_path)
    assert "API_SECRET=super_secret_value" in txt

    # Remove mock:key-1
    removed = remove_kms_from_vault(vault_path, "mock:key-1")
    assert removed is True
    slots_after_remove = list_kms_slots(vault_path)
    assert len(slots_after_remove) == 1
    assert slots_after_remove[0]["key_id"] == "key-2"


def test_aws_kms_provider_with_mock() -> None:
    aws_provider = AwsKmsProvider()

    mock_boto_client = mock.MagicMock()
    mock_boto_client.encrypt.return_value = {"CiphertextBlob": b"aws_encrypted_blob"}
    mock_boto_client.decrypt.return_value = {"Plaintext": b"thirty_two_byte_decrypted_dek_12"}

    with mock.patch.object(aws_provider, "_get_boto3_client", return_value=mock_boto_client):
        cipher, meta = aws_provider.encrypt(b"thirty_two_byte_decrypted_dek_12", "arn:aws:kms:eu-central-1:123:key/k")
        assert meta["region"] == "eu-central-1"
        assert cipher == base64.b64encode(b"aws_encrypted_blob").decode("utf-8")

        plain = aws_provider.decrypt(cipher, "arn:aws:kms:eu-central-1:123:key/k", meta)
        assert plain == b"thirty_two_byte_decrypted_dek_12"


def test_aws_kms_missing_boto3() -> None:
    aws_provider = AwsKmsProvider()
    with mock.patch.dict("sys.modules", {"boto3": None}):
        with pytest.raises(KmsProviderError, match="requires 'boto3'"):
            aws_provider.encrypt(b"x" * 32, "arn:aws:kms:us-east-1:123:key/k")


def test_gcp_kms_provider_with_mock() -> None:
    gcp_provider = GcpKmsProvider()

    mock_kms_client = mock.MagicMock()
    mock_resp_encrypt = mock.MagicMock()
    mock_resp_encrypt.ciphertext = b"gcp_cipher_blob"
    mock_resp_encrypt.name = "v1"
    mock_kms_client.encrypt.return_value = mock_resp_encrypt

    mock_resp_decrypt = mock.MagicMock()
    mock_resp_decrypt.plaintext = b"thirty_two_byte_gcp_secret_dek_3"
    mock_kms_client.decrypt.return_value = mock_resp_decrypt

    with mock.patch.object(gcp_provider, "_get_kms_client", return_value=mock_kms_client):
        cipher, meta = gcp_provider.encrypt(b"dek", "projects/p/locations/l/keyRings/r/cryptoKeys/k")
        assert meta["key_version"] == "v1"

        plain = gcp_provider.decrypt(cipher, "projects/p/locations/l/keyRings/r/cryptoKeys/k", meta)
        assert plain == b"thirty_two_byte_gcp_secret_dek_3"


def test_azure_kms_provider_with_mock() -> None:
    azure_provider = AzureKeyVaultProvider()

    mock_crypto_client = mock.MagicMock()
    mock_enc_res = mock.MagicMock()
    mock_enc_res.ciphertext = b"azure_ciphertext_blob"
    mock_crypto_client.encrypt.return_value = mock_enc_res

    mock_dec_res = mock.MagicMock()
    mock_dec_res.plaintext = b"thirty_two_byte_azure_dek_val_99"
    mock_crypto_client.decrypt.return_value = mock_dec_res

    with mock.patch.object(azure_provider, "_get_crypto_client", return_value=mock_crypto_client):
        with mock.patch.dict("sys.modules", {"azure.keyvault.keys.crypto": mock.MagicMock()}):
            cipher, meta = azure_provider.encrypt(b"dek", "https://v.vault.azure.net/keys/k")
            assert meta["algorithm"] == "rsa_oaep_256"

            plain = azure_provider.decrypt(cipher, "https://v.vault.azure.net/keys/k", meta)
            assert plain == b"thirty_two_byte_azure_dek_val_99"


def test_hashicorp_vault_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "s.root_token_test")

    vault_provider = HashiCorpVaultProvider()
    avail, msg = vault_provider.is_available()
    assert avail is True
    assert "VAULT_TOKEN detected" in msg

    mock_post_encrypt = mock.MagicMock()
    mock_post_encrypt.status_code = 200
    mock_post_encrypt.json.return_value = {"data": {"ciphertext": "vault:v1:fake_ciphertext_data"}}

    mock_post_decrypt = mock.MagicMock()
    mock_post_decrypt.status_code = 200
    b64_plain = base64.b64encode(b"thirty_two_byte_vault_dek_secret").decode("utf-8")
    mock_post_decrypt.json.return_value = {"data": {"plaintext": b64_plain}}

    with mock.patch("requests.post", side_effect=[mock_post_encrypt, mock_post_decrypt]):
        cipher, meta = vault_provider.encrypt(b"secret", "vault:transit/my-app-key")
        assert meta["vault_addr"] == "http://127.0.0.1:8200"

        plain = vault_provider.decrypt(cipher, "vault:transit/my-app-key", meta)
        assert plain == b"thirty_two_byte_vault_dek_secret"


def test_ci_workflow_generator() -> None:
    github_wf = generate_ci_workflow("github", "arn:aws:kms:us-east-1:123:key/xyz")
    assert "aws-actions/configure-aws-credentials" in github_wf
    assert "envshield run -- python -m pytest" in github_wf

    gitlab_wf = generate_ci_workflow("gitlab", "arn:aws:kms:us-east-1:123:key/xyz")
    assert ".gitlab-ci.yml" in gitlab_wf
    assert "envshield run" in gitlab_wf


def test_cli_kms_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("CLIENT_ID=abc\nCLIENT_SECRET=xyz\n", encoding="utf-8")
    enc_file = tmp_path / ".env.enc"

    # Test CLI seal with --kms and --no-password
    with pytest.raises(SystemExit) as exc:
        main(["seal", str(env_file), "-o", str(enc_file), "--no-password", "--kms", "mock:cli-key-1"])
    assert exc.value.code == 0
    assert enc_file.is_file()

    # Test CLI kms test
    with pytest.raises(SystemExit) as exc:
        main(["kms", "test", "mock:cli-key-1"])
    assert exc.value.code == 0

    # Test CLI kms list
    with pytest.raises(SystemExit) as exc:
        main(["kms", "list", str(enc_file)])
    assert exc.value.code == 0

    # Test CLI kms add
    with pytest.raises(SystemExit) as exc:
        main(["kms", "add", "mock:cli-key-2", str(enc_file)])
    assert exc.value.code == 0

    slots = list_kms_slots(enc_file)
    assert len(slots) == 2

    # Test CLI kms remove
    with pytest.raises(SystemExit) as exc:
        main(["kms", "remove", "mock:cli-key-1", str(enc_file)])
    assert exc.value.code == 0

    slots_after = list_kms_slots(enc_file)
    assert len(slots_after) == 1
    assert slots_after[0]["key_id"] == "cli-key-2"

    # Test CLI ci init
    ci_out = tmp_path / ".github" / "workflows" / "envshield.yml"
    with pytest.raises(SystemExit) as exc:
        main(["ci", "init", "--provider", "github", "-o", str(ci_out)])
    assert exc.value.code == 0
    assert ci_out.is_file()
    assert "envshield run" in ci_out.read_text(encoding="utf-8")
