<div align="center">

<img src="assets/banner.svg" alt="Envshield Banner" width="100%" />

<br>

[![PyPI Version](https://img.shields.io/pypi/v/envshield-cli?style=flat-square&logo=pypi&logoColor=white&label=PyPI&color=10B981)](https://pypi.org/project/envshield-cli/)
[![Python Versions](https://img.shields.io/pypi/pyversions/envshield-cli?style=flat-square&logo=python&logoColor=white&label=Python&color=3B82F6)](https://pypi.org/project/envshield-cli/)
[![Cryptography](https://img.shields.io/badge/Cipher-AES--256--GCM-6366F1?style=flat-square&logo=letsencrypt&logoColor=white)](https://github.com/AmhetCnaa/Envshield)
[![Memory Protection](https://img.shields.io/badge/Memory-VirtualLock%20%2F%20mlock-059669?style=flat-square)](https://github.com/AmhetCnaa/Envshield)
[![License](https://img.shields.io/badge/License-MIT-334155?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-30-second-quickstart"><b>Quickstart</b></a> •
  <a href="#-why-envshield"><b>Why Envshield?</b></a> •
  <a href="#-team-ssh-workflow"><b>Team SSH Vaults</b></a> •
  <a href="#-command-suite"><b>Command Suite</b></a> •
  <a href="#-zero-disk-architecture"><b>Architecture</b></a>
</p>

<img src="assets/terminal-demo.svg" alt="Envshield Terminal Demo" width="100%" />

</div>

---

## ⚡ 30-Second Quickstart

```bash
# 1. Install
pip install envshield-cli

# 2. Seal your .env into an encrypted vault & shred the plaintext file
envshield seal .env --shred

# 3. Run any application with secrets streamed directly from locked RAM
envshield run -- python app.py
```

> [!TIP]
> **Language Agnostic:** Replace `python app.py` with `npm run dev`, `cargo run`, `go run main.go`, `uvicorn`, or any binary. Your application reads standard environment variables with **zero code changes**.

---

## 🛡️ Why Envshield?

Plaintext `.env` files sitting on developer laptops and CI servers are the #1 source of credential leaks. **Envshield** replaces fragile plaintext files with a hardened, zero-disk cryptographic workflow:

| Traditional `.env` Workflow | The `envshield` Standard |
| :--- | :--- |
| ❌ **Disk Exposure:** Plaintext secrets persist on SSD blocks & backups | ✅ **Zero-Disk Invariant:** Decrypted strictly in volatile RAM; never touches disk |
| ❌ **Git Leaks:** One accidental `git add .` exposes production keys | ✅ **Git-Safe Vaults:** Commit `.env.enc` directly to your repository with confidence |
| ❌ **Swap Leaks:** OS kernel pages plaintext memory into `pagefile.sys` | ✅ **Hardware Page Locking:** Memory locked via `VirtualLock` / `mlock` + zero-wiped |
| ❌ **Password Sprawl:** Sharing master passwords over Slack or DMs | ✅ **Team SSH Keys:** Seal vaults using teammates' `id_ed25519.pub` / `id_rsa.pub` |

---

## 🧠 Zero-Disk Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="Envshield Zero-Disk Architecture" width="100%" />
</div>

---

## 👥 Team SSH Workflow

Stop sharing passwords across Slack. Envshield's **Envelope v2** cryptography lets you seal a vault for multiple teammates using their existing OpenSSH public keys:

```bash
# Encrypt .env for multiple team members (no shared password needed)
envshield seal .env \
  -r ~/.ssh/id_ed25519.pub \
  -r ~/.ssh/teammate_ed25519.pub \
  -r ~/.ssh/devops_rsa.pub \
  --no-password
```

Each authorized developer unlocks and runs the project using their own local SSH private key:

```bash
envshield run -i ~/.ssh/id_ed25519 -- npm start
```

---

## 🧰 Command Suite

<table>
<tr>
<td width="50%" valign="top">

### 🔒 `envshield seal`
Encrypt `.env`, `.json`, `.toml`, or `.yaml` files into authenticated `.enc` vaults.
```bash
# Seal with password + shred original
envshield seal .env --shred

# Seal with SSH recipient key
envshield seal .env -r ~/.ssh/id_ed25519.pub
```

</td>
<td width="50%" valign="top">

### 🚀 `envshield run`
Decrypt in RAM and inject variables directly into the child process.
```bash
# Interactive or OS Keyring unlock
envshield run -- python manage.py runserver

# Headless CI/CD pipeline execution
ENVSHIELD_KEY="secret" envshield run -- ./deploy.sh
```

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📝 `envshield edit`
Modify encrypted secrets in-place inside `$EDITOR` (`vim`, `nano`, `code`, `notepad`).
```bash
# Opens isolated buffer & shreds on exit
envshield edit .env.enc
```

</td>
<td width="50%" valign="top">

### 🔍 `envshield diff`
Compare two encrypted vaults or inspect changes in RAM with colored unified diffs.
```bash
# Compare staging vs production vaults in RAM
envshield diff staging.env.enc prod.env.enc
```

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔑 `envshield key`
Store vault passphrases in Windows Credential Manager, macOS Keychain, or Linux Secret Service.
```bash
envshield key set prod_vault
envshield run --keyring-name prod_vault -- node index.js
```

</td>
<td width="50%" valign="top">

### 🕵️ `envshield scan`
Audit source code and Git staging area for hardcoded API tokens and high-entropy leaks.
```bash
envshield --staged
envshield --install-hook
```

</td>
</tr>
</table>

---

## 📊 Comparison Matrix

| Capability | `envshield` | `dotenv` | `sops` | `HashiCorp Vault` | `1Password CLI` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **100% RAM-Only Injection** | ✅ | ❌ | ⚠️ Partial | ✅ | ✅ |
| **SSH Public Key Recipients** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Anti-Swap Memory Lock (`mlock`)** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **In-Memory Vault Diff (`diff`)** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Native OS Keychain (`key`)** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Zero Infrastructure / Offline** | ✅ | ✅ | ✅ | ❌ Server | ❌ Cloud Account |
| **Cold-Start Overhead** | **< 25 ms** | ~ 5 ms | ~ 60 ms | ~ 200 ms | ~ 120 ms |

---

<details>
<summary><b>🔬 Deep Dive: Cryptographic Specifications & Python API</b></summary>
<br>

### Cryptographic Primitives
* **AEAD Payload Cipher:** `AES-256-GCM` with 96-bit CSPRNG nonces and 128-bit authentication tags.
* **Key Derivation:** `PBKDF2-HMAC-SHA256` (100,000 iterations, 16-byte random salt).
* **Asymmetric Key Exchange:** Ephemeral-Static `X25519` ECDH (via birational Ed25519 curve mapping) + `HKDF-SHA256`, and `RSA-OAEP-SHA256`.
* **Forensic Sanitization:** 3-pass random overwrite (`os.urandom`), zero-fill pass (`0x00`), `os.fsync()` hardware cache flush, and `ctypes.memset` RAM zeroing.

### Python SDK Usage
```python
from pathlib import Path
from envshield.core.vault import seal_file, unseal_to_memory
from envshield.core.runner import execute_with_env

# Encrypt file
seal_file(Path(".env"), Path(".env.enc"), password="StrongPassword!")

# Decrypt directly into a Python dictionary in RAM (zero disk writes)
secrets = unseal_to_memory(Path(".env.enc"), password="StrongPassword!")

# Run command with injected environment
exit_code = execute_with_env(["python", "worker.py"], secrets)
```

</details>

---

<div align="center">
  <sub>Released under the <a href="LICENSE">MIT License</a> • Built for developers who care about security.</sub>
</div>
