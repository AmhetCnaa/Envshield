# envshield

<p align="center">
  <strong>Zero-Disk Secret Engine & Runtime Injection for Developers</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/envshield-cli/"><img src="https://img.shields.io/pypi/v/envshield-cli.svg?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/envshield-cli/"><img src="https://img.shields.io/pypi/pyversions/envshield-cli.svg" alt="Python versions"></a>
  <img src="https://img.shields.io/badge/security-AES--256--GCM-green.svg" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/memory-zero--disk--leak-success.svg" alt="Zero-Disk Writes">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

---

## Overview

Modern software development relies heavily on `.env` files for configuration, database credentials, third-party API tokens, and production keys. However, unencrypted `.env` files represent one of the most common vectors for credential exfiltration, accidental Git commits, filesystem backups, and container image leaks.

**envshield** eliminates secret leakage on developer workstations and CI/CD pipelines using an ephemeral **Zero-Disk Writes** architecture combined with military-grade **AES-256-GCM** encryption. Secrets are decrypted strictly in process RAM and streamed directly to child processes through memory pipelines without ever touching disk storage or swap files.

---

## Core Philosophy: Zero-Disk Writes

Traditional secret loaders (like `python-dotenv` or decrypted files) leave plaintext traces on the filesystem block layer, swap files, and temporary directories (`/tmp`). 

`envshield` operates under a strict **Zero-Disk Invariant**:
1. **Encrypted at Rest**: `.env.enc` files are sealed using authenticated ciphertext.
2. **RAM-Only Decryption**: The master key decrypts secrets directly into volatile memory buffers (`bytes` / `str`).
3. **Process-Level Injection**: Secrets are injected directly into child process environment maps (`merged_env = os.environ.copy(); merged_env.update(secrets)`).
4. **Instant Garbage Collection**: Plaintext buffers are released from RAM as soon as execution handoff completes. No unsealed file is ever written to disk.

```
       ┌───────────────┐
       │   .env.enc    │ (Encrypted on Disk)
       └───────┬───────┘
               │
               ▼ [Read into memory buffer]
    ╔══════════════════════════════════════════════════════════╗
    ║                     RAM / MEMORY ONLY                    ║
    ║                                                          ║
    ║   1. PBKDF2-SHA256 (100k iter) ──► Derive AES-256 Key   ║
    ║   2. AES-256-GCM Authenticated Decryption                ║
    ║   3. In-memory .env Key-Value Parsing                    ║
    ║   4. Inject into os.environ.copy()                       ║
    ╚══════════════════════════════════════════════════════════╝
               │
               ▼ [Stream to subprocess via execve / fork]
       ┌───────────────┐
       │ Child Process │ (e.g., python app.py, uvicorn, node)
       └───────────────┘
```

---

## Cryptographic Architecture

`envshield` implements standard NIST-recommended cryptographic primitives via Python's `cryptography` (hazmat) engine:

| Primitive | Parameter | Specification / Purpose |
| :--- | :--- | :--- |
| **Cipher** | `AES-256-GCM` | Authenticated Encryption with Associated Data (AEAD). Guarantees confidentiality and tamper-proof integrity. |
| **Key Derivation** | `PBKDF2HMAC` | Derives 256-bit symmetric keys from human passwords or machine passphrases. |
| **KDF Digest** | `SHA-256` | Cryptographic hash function powering PBKDF2 HMAC operations. |
| **KDF Iterations**| `100,000` | Resistant to high-speed offline GPU/ASIC brute-force dictionary attacks. |
| **Salt** | `16 bytes` | CSPRNG salt generated per encryption via `os.urandom(16)`. Prevents rainbow table attacks. |
| **Nonce / IV** | `12 bytes` | Standard 96-bit unique random nonce (`os.urandom(12)`) per ciphertext. |
| **Authentication Tag** | `16 bytes` | Poly1305/GHASH authentication tag verifying ciphertext authenticity. |
| **Payload Layout** | Binary / Base64 | `[ Salt (16B) ] + [ Nonce (12B) ] + [ Ciphertext + Tag (N+16B) ]` |

### Multi-Pass File Shredding (`--shred`)
When sealing environment files, `envshield` provides a secure shredding routine to prevent forensic block recovery:
- Overwrites the target file blocks with cryptographically secure random bytes (`os.urandom`) across multiple passes.
- Final pass zeros out the allocated blocks (`b"\x00"`).
- Calls `os.fsync()` to force disk controllers to flush hardware write buffers before calling `unlink()`.

---

## Benchmark & Architectural Comparison

| Feature / Metric | `envshield` | Plain `.env` / `dotenv` | `Ansible Vault` | `HashiCorp Vault` | `1Password CLI` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Zero-Disk Writes** | **Yes (100% RAM)** | No (Plaintext on disk) | Partial (Temp files) | Yes (Network fetch) | Yes (IPC / Pipe) |
| **Setup Complexity** | **Zero Config (CLI)** | Zero Config | Medium (Ansible setup) | High (Server / Cluster) | High (Account / Daemon) |
| **Cold-Start Overhead** | **< 30 ms** | ~ 5 ms | ~ 350 ms | ~ 150-400 ms (HTTP) | ~ 120 ms |
| **Git Safety** | **Safe (`.env.enc`)** | Dangerous | Safe | Safe | Safe |
| **Offline / Air-Gapped**| **Full Support** | Full Support | Full Support | Requires Network | Requires Agent |
| **Tamper Detection** | **Yes (AEAD Tag)** | None | Yes (HMAC) | Yes (TLS + Token) | Yes (TLS) |
| **Integrated Scanners** | **Yes (Regex+Entropy)** | None | None | None | None |

---

## Installation

```bash
pip install envshield-cli
```

Or install with development dependencies:

```bash
pip install "envshield-cli[dev]"
```

---

## CLI Command Reference

### 1. `envshield seal` — Encrypt Secrets Vault

Encrypts an unencrypted `.env` file into a secure `.env.enc` vault.

```bash
# Encrypt default .env to .env.enc (prompts securely for password)
envshield seal

# Encrypt a specific environment file
envshield seal .env.production

# Encrypt and specify custom output target
envshield seal .env.staging -o staging.enc

# Encrypt and securely shred the original unencrypted file
envshield seal .env --shred
```

> **Tip:** You can supply your password non-interactively via the `ENVSHIELD_KEY` environment variable in automated workflows.

---

### 2. `envshield run` — In-Memory Execution Injection

Decrypts your vault entirely in volatile memory and streams standard process input/output directly to your terminal.

```bash
# Run a Python service with secrets loaded into RAM
envshield run -- python app.py

# Run FastAPI or Uvicorn server
envshield run -- uvicorn main:app --host 0.0.0.0 --port 8000

# Run with a custom encrypted file
envshield run --env-file staging.enc -- npm start

# Run database migrations
envshield run -- alembic upgrade head
```

#### Automated CI/CD Execution
For headless containers (Docker, GitHub Actions, GitLab CI, Kubernetes):

```bash
export ENVSHIELD_KEY="your-secure-ci-passphrase"
envshield run --env-file .env.production.enc -- ./deploy.sh
```

---

### 3. Integrated Security Auditing & Git Hooks

`envshield` also includes enterprise static scanners to prevent secrets from slipping into source control:

```bash
# Scan working directory for leaked API keys, tokens, and high-entropy strings
envshield .

# Scan only Git staged files before commit
envshield --staged

# CI/CD mode (returns non-zero exit code on findings with SARIF or JSON output)
envshield --ci --format sarif > report.sarif
envshield --ci --format json > report.json

# Install pre-commit Git hook automatically
envshield --install-hook
```

---

## Python API Usage

You can also leverage `envshield`'s zero-disk engine directly within your Python applications:

```python
from pathlib import Path
from envshield.core.vault import seal_file, unseal_to_memory
from envshield.core.runner import execute_with_env

# 1. Seal an environment file
seal_file(Path(".env"), Path(".env.enc"), password="YourStrongPassword123!")

# 2. Unseal directly into memory (returns dict, never writes plaintext to disk)
secrets = unseal_to_memory(Path(".env.enc"), password="YourStrongPassword123!")
print("Database host:", secrets["DB_HOST"])

# 3. Execute subprocess with in-memory secrets injection
exit_code = execute_with_env(["python", "worker.py"], secrets)
```

---

## Threat Model & Security Practices

- **Memory Dump Resistance**: Plaintext strings reside in Python process memory. Operating system level permissions isolate this memory from unauthorized users.
- **No Residual Swapping**: In sensitive production hosts, combine `envshield` with `mlock` or disable swap partitions to guarantee memory pages are never written to disk by the kernel.
- **Passphrase Entropy**: Use high-entropy passphrases (>= 16 characters or random passphrases). The PBKDF2-SHA256 stretching function with 100,000 rounds ensures resilience against brute-force attempts.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
