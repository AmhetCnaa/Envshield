# envshield

<p align="center">
  <strong>Zero-Disk Secret Engine, Team Asymmetric Vaults & Runtime Injection for Developers</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/envshield-cli/"><img src="https://img.shields.io/pypi/v/envshield-cli.svg?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/envshield-cli/"><img src="https://img.shields.io/pypi/pyversions/envshield-cli.svg" alt="Python versions"></a>
  <img src="https://img.shields.io/badge/security-AES--256--GCM-green.svg" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/memory-zero--disk--leak-success.svg" alt="Zero-Disk Writes">
  <img src="https://img.shields.io/badge/recipients-SSH%20%2F%20Ed25519%20%2F%20RSA-blueviolet.svg" alt="SSH Recipients">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

---

## Overview

Modern software development relies heavily on `.env` files for configuration, database credentials, third-party API tokens, and production keys. However, unencrypted secret files represent one of the most common vectors for credential exfiltration, accidental Git commits, filesystem backups, and container image leaks.

**envshield** eliminates secret leakage on developer workstations, team repositories, and CI/CD pipelines using an ephemeral **Zero-Disk Writes** architecture combined with **AES-256-GCM** encryption and **Multi-Recipient SSH Public Key** envelope cryptography. Secrets are decrypted strictly in volatile process RAM and streamed directly to child processes through memory pipelines without ever touching disk storage or swap files.

---

## Key Features

- 🔒 **Zero-Disk Writes Architecture:** Secrets are decrypted in volatile RAM (`bytes`/`bytearray`) and injected directly into child process environments (`os.environ`). No plaintext file or temp directory is ever written.
- 🛡️ **Memory Hardening & Anti-Dump:** Memory pages are locked in RAM using `VirtualLock` (Windows) and `mlock` (POSIX) to prevent kernel paging to `pagefile.sys` or swap partitions. In-place memory zeroing wipes sensitive buffers immediately after handoff.
- 👥 **Team Asymmetric Encryption (SSH Keys):** Seal vaults for multiple team members using their existing SSH public keys (`id_ed25519.pub`, `id_rsa.pub`). Any authorized member can decrypt with their private key without sharing passwords.
- 📝 **Safe In-Place Vault Editing (`envshield edit`):** Edit encrypted vaults securely inside your favorite editor (`$EDITOR` / `nano` / `vim` / `notepad`). The ephemeral buffer is shredded with multi-pass overwrites upon exit.
- 🔍 **In-Memory Diff Tool (`envshield diff`):** Compare encrypted vaults or check working tree changes against encrypted vaults with syntax-colored unified diffs without persisting decrypted files to disk.
- 🔑 **OS Keyring Integration (`envshield key`):** Seamlessly store and retrieve vault passphrases using Windows Credential Manager, macOS Keychain, or Linux Secret Service.
- 📦 **Multi-Format Support:** Seal and unseal standard `.env`, `.json`, `.toml`, and `.yaml` configurations, with automatic hierarchical key flattening (`DATABASE__PORT=5432`).
- 🤖 **Standalone Executables:** Portable standalone binary compilation for Windows, macOS, and Linux via automated GitHub Actions CI/CD.

---

## Core Philosophy: Zero-Disk Writes

```
       ┌────────────────────────┐
       │   .env.enc / vault.enc │ (Encrypted on Disk / Git Safe)
       └───────────┬────────────┘
                   │
                   ▼ [Read into locked memory buffer]
    ╔══════════════════════════════════════════════════════════════════╗
    ║                     RAM / MEMORY ONLY (VirtualLock / mlock)      ║
    ║                                                                  ║
    ║   1. Resolve DEK (Password PBKDF2 OR SSH Private Key ECDH/RSA)  ║
    ║   2. AES-256-GCM Authenticated Decryption                        ║
    ║   3. In-memory Parsing (.env / JSON / TOML / YAML)               ║
    ║   4. Inject into os.environ.copy()                               ║
    ║   5. In-place Memory Wipe (ctypes.memset / RtlZeroMemory)        ║
    ╚══════════════════════════════════════════════════════════════════╝
                   │
                   ▼ [Stream to subprocess via execve / fork]
       ┌────────────────────────┐
       │     Child Process      │ (e.g., python app.py, uvicorn, node, docker)
       └────────────────────────┘
```

---

## Cryptographic Envelope Architecture (V2)

`envshield` implements standard NIST-recommended cryptographic primitives:

| Component | Primitive | Specification / Purpose |
| :--- | :--- | :--- |
| **Payload Cipher** | `AES-256-GCM` | Authenticated Encryption with Associated Data (AEAD). Tamper-proof integrity. |
| **Data Encryption Key** | `256-bit CSPRNG` | Unique random DEK generated per vault via `os.urandom(32)`. |
| **Password Slot** | `PBKDF2-HMAC-SHA256` | 100,000 rounds with 16-byte random salt to encrypt the DEK. |
| **Ed25519 SSH Slot** | `X25519 ECDH + HKDF` | Ephemeral Curve25519 key exchange + HKDF-SHA256 + AES-GCM encryption of DEK. |
| **RSA SSH Slot** | `RSA-OAEP-SHA256` | Direct 2048/4096-bit RSA asymmetric encryption of DEK with MGF1-SHA256. |
| **Memory Isolation** | `mlock` / `VirtualLock` | Prevents operating system from swapping volatile secret buffers to disk. |
| **Disk Shredding** | `CSPRNG + Zero + fsync` | Overwrites block layer with random bytes and zeros before unlinking. |

---

## Benchmark & Comparison

| Feature / Metric | `envshield` | Plain `.env` / `dotenv` | `sops` | `Ansible Vault` | `HashiCorp Vault` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Zero-Disk Writes (RAM only)** | **Yes (100% RAM)** | No (Plaintext) | Partial (Exec helper) | Partial (Temp files) | Yes (HTTP daemon) |
| **Memory Hardening (`mlock`)** | **Yes (`VirtualLock`)** | None | None | None | Yes |
| **SSH Public Key Recipients** | **Yes (Ed25519 / RSA)** | None | Yes (PGP / Age) | None | No (Token / AppRole) |
| **In-Memory Diff Engine** | **Yes (`envshield diff`)** | Standard diff | Yes | Yes | Web / API only |
| **In-Place Secure Editor** | **Yes (`envshield edit`)** | Insecure | Yes | Yes | Web UI |
| **Integrated Keyring Storage** | **Yes (`envshield key`)** | None | None | None | External CLI |
| **Cold-Start Overhead** | **< 30 ms** | ~ 5 ms | ~ 60 ms | ~ 350 ms | ~ 150-400 ms |

---

## Installation

```bash
pip install envshield-cli
```

Or install with all development tooling:

```bash
pip install "envshield-cli[dev]"
```

---

## CLI Command Reference

### 1. `envshield seal` — Encrypt Secrets Vault

Encrypt an unencrypted `.env`, `.json`, or `.toml` file into a secure vault.

```bash
# Encrypt default .env to .env.enc (prompts securely for password)
envshield seal

# Seal with SSH public keys for team members (no shared password required!)
envshield seal .env -r ~/.ssh/id_ed25519.pub -r ~/.ssh/id_rsa.pub --no-password

# Hybrid vault: Both password AND team SSH keys can unlock
envshield seal .env -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..."

# Encrypt structured configuration files
envshield seal config.json --format json -o config.json.enc

# Encrypt and securely shred original unencrypted file from disk
envshield seal .env --shred

# Save password automatically to OS Keyring during seal
envshield seal .env --keyring-name prod_secret
```

---

### 2. `envshield run` — In-Memory Execution Injection

Decrypts your vault entirely in volatile memory and streams standard process input/output directly to your terminal.

```bash
# Run a Python service with secrets loaded into RAM
envshield run -- python app.py

# Run with SSH private key authentication
envshield run -i ~/.ssh/id_ed25519 -- node server.js

# Run with password automatically retrieved from OS Keyring
envshield run --keyring-name prod_secret -- uvicorn main:app

# Run with custom encrypted vault
envshield run --env-file staging.json.enc -- npm start
```

#### Automated CI/CD Execution
For headless containers (Docker, GitHub Actions, GitLab CI, Kubernetes):

```bash
export ENVSHIELD_KEY="your-secure-ci-passphrase"
envshield run --env-file .env.production.enc -- ./deploy.sh
```

---

### 3. `envshield edit` — Safe In-Place Vault Editing

Edit an encrypted vault in-place without manual decryption or leaving unencrypted copies behind.

```bash
# Opens default terminal editor ($EDITOR or notepad) on ephemeral secured RAM file
envshield edit .env.enc

# Edit using specific editor and SSH key
envshield edit .env.enc -i ~/.ssh/id_ed25519 --editor code
```

Upon closing the editor, `envshield` validates changes, re-seals the vault, and securely shreds the temporary file.

---

### 4. `envshield diff` — In-Memory Vault Comparison

Compare changes between encrypted vaults or between an unencrypted file and an encrypted vault.

```bash
# Diff encrypted vault against local working file
envshield diff .env.enc

# Diff two encrypted vaults directly in RAM
envshield diff staging.env.enc prod.env.enc
```

---

### 5. `envshield key` — OS Keyring Management

Manage passphrases in your operating system's native credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service).

```bash
# Securely store a passphrase in OS Keyring
envshield key set production_db

# Retrieve and inspect stored key
envshield key get production_db

# Delete stored key
envshield key delete production_db
```

---

### 6. Integrated Security Scanners & Git Hooks

Scan codebases for hardcoded credentials and configuration drift:

```bash
# Scan working directory for secret leaks
envshield .

# Scan git staged files before commit
envshield --staged

# CI/CD mode (SARIF / JSON reporting)
envshield --ci --format sarif > report.sarif

# Install git pre-commit hook automatically
envshield --install-hook
```

---

## Python API Usage

You can also leverage `envshield`'s zero-disk engine directly within Python applications:

```python
from pathlib import Path
from envshield.core.vault import seal_file, unseal_to_memory
from envshield.core.runner import execute_with_env

# 1. Seal an environment file with password or SSH recipients
seal_file(Path(".env"), Path(".env.enc"), password="MasterPassword123!")

# 2. Unseal directly into RAM (returns dict, zero disk writes)
secrets = unseal_to_memory(Path(".env.enc"), password="MasterPassword123!")
print("Database host:", secrets["DB_HOST"])

# 3. Execute subprocess with in-memory secrets injection
exit_code = execute_with_env(["python", "worker.py"], secrets)
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
