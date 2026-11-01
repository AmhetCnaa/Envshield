<div align="center">

# 🛡️ envshield

**Zero-Disk Secret Engine & Runtime Injection for Developers**

Never commit plaintext `.env` files again. Encrypt once, share securely, and inject secrets directly from RAM without touching disk storage.

[![PyPI version](https://img.shields.io/pypi/v/envshield-cli.svg?style=flat-square&color=blue)](https://pypi.org/project/envshield-cli/)
[![Python](https://img.shields.io/pypi/pyversions/envshield-cli.svg?style=flat-square)](https://pypi.org/project/envshield-cli/)
[![Security](https://img.shields.io/badge/encryption-AES--256--GCM-2ea44f.svg?style=flat-square)](https://github.com/AmhetCnaa/Envshield)
[![Zero Disk](https://img.shields.io/badge/storage-zero--disk--leak-success.svg?style=flat-square)](https://github.com/AmhetCnaa/Envshield)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

</div>

---

## 💡 Why envshield?

Every developer relies on `.env` files for API tokens and database credentials. But plaintext secrets pose serious risks: accidental Git pushes, disk forensic recovery, and leaks in Docker containers.

**envshield** fixes this with three simple principles:
1. **Zero-Disk Invariant:** Secrets are decrypted **strictly in RAM** and passed directly to child process memory. No temporary files, no plaintext left on disk.
2. **Team-First Security:** Seal vaults using your teammates' existing **SSH public keys** (`id_ed25519.pub`, `id_rsa.pub`). No shared passwords required.
3. **Zero Code Changes:** Works with any language or runtime—Python, Node.js, Go, Rust, Ruby, Docker, or shell scripts.

---

## ⚡ Quick Start (in 30 seconds)

### 1. Install

```bash
pip install envshield-cli
```

### 2. Lock Your Secrets

Encrypt your `.env` into a secure `.env.enc` vault and wipe the unencrypted file from disk:

```bash
envshield seal .env --shred
```
*(Now `.env.enc` is completely safe to commit to Git!)*

### 3. Run Your Application

Decrypt on-the-fly in RAM and stream execution directly to your app:

```bash
envshield run -- python app.py
```
*(Replace `python app.py` with `npm start`, `uvicorn main:app`, `cargo run`, or any command)*

---

## 🚀 Everyday Workflows

### 👥 1. Team Collaboration (No Shared Passwords)
Encrypt a vault for multiple teammates using their SSH keys:

```bash
# Seal for yourself and your teammates
envshield seal .env -r ~/.ssh/id_ed25519.pub -r ~/.ssh/alice_rsa.pub --no-password

# Anyone with their authorized private key runs smoothly:
envshield run -i ~/.ssh/id_ed25519 -- npm start
```

---

### 📝 2. Edit Secrets In-Place (`envshield edit`)
Need to add or update an API key? Don't decrypt to disk. Open an ephemeral buffer in your favorite editor:

```bash
envshield edit .env.enc
```
*`envshield` opens your editor (`$EDITOR` or `notepad`), re-encrypts changes on save, and shreds the temporary memory buffer automatically.*

---

### 🔍 3. Compare Vaults Without Decrypting (`envshield diff`)
Inspect differences between encrypted vaults or against your local changes directly in the terminal:

```bash
# Diff encrypted vault against working tree
envshield diff .env.enc

# Diff two environment vaults (staging vs prod)
envshield diff staging.env.enc prod.env.enc
```

---

### 🔑 4. Save Password to OS Keyring (`envshield key`)
Never re-type passwords again. Store credentials securely in Windows Credential Manager, macOS Keychain, or Linux Secret Service:

```bash
# Save vault password
envshield key set my_project

# Run automatically with stored credential
envshield run --keyring-name my_project -- python main.py
```

---

### 🤖 5. CI / CD & Headless Automation
Supply the vault key non-interactively in Docker, GitHub Actions, or Kubernetes:

```bash
export ENVSHIELD_KEY="your-production-vault-key"
envshield run --env-file .env.prod.enc -- ./deploy.sh
```

---

## 🧠 How It Works

```text
       ┌──────────────┐
       │   .env.enc   │  ◄── Safely committed to Git (AES-256-GCM)
       └──────┬───────┘
              │
              ▼  [Loaded into locked RAM pages]
    ╔════════════════════════════════════════════════════════════════╗
    ║                     VOLATILE RAM BUFFER                        ║
    ║                                                                ║
    ║   • Authenticate via Password OR SSH Private Key               ║
    ║   • AES-256-GCM Decrypt strictly in memory                     ║
    ║   • Lock memory against swap writes (VirtualLock / mlock)      ║
    ║   • Inject secrets directly into os.environ.copy()             ║
    ║   • Overwrite & zero RAM buffer immediately                    ║
    ╚════════════════════════════════════════════════════════════════╝
              │
              ▼  [Streams directly to child process]
       ┌──────────────┐
       │  Your App    │  (Python, Node.js, Go, Rust, Docker...)
       └──────────────┘
```

---

## 📊 Comparison

| Feature | `envshield` | Plain `.env` | `sops` | `HashiCorp Vault` |
| :--- | :---: | :---: | :---: | :---: |
| **Zero-Disk Writes (RAM only)** | **Yes** | ❌ No | Partial | ❌ Requires Daemon |
| **SSH Public Key Recipients** | **Yes** | ❌ No | ❌ (PGP / Age) | ❌ (Token auth) |
| **Memory Page Locking (`mlock`)** | **Yes** | ❌ No | ❌ No | **Yes** |
| **In-Memory Diff Tool** | **Yes** | ❌ Plaintext | **Yes** | ❌ Web / API only |
| **Setup Overhead** | **Zero (< 1 min)**| Zero | Medium | High (Server Setup) |
| **Cold Start Delay** | **< 30 ms** | ~ 5 ms | ~ 60 ms | ~ 200 ms |

---

## 📦 Supported Formats

`envshield` automatically handles multiple configuration formats:

* **`.env` files:** Standard `KEY=VALUE` pairs, `export KEY=VALUE`, and comments.
* **`.json` files:** Flattened hierarchically (`{"db": {"port": 5432}}` ➔ `DB__PORT=5432`).
* **`.toml` files:** Native TOML table support.
* **`.yaml` files:** YAML mapping support.

---

## 🔒 Security & Cryptography

* **AEAD Cipher:** AES-256-GCM authenticated encryption (128-bit authentication tag).
* **Key Derivation:** PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salt.
* **Asymmetric Exchange:** OpenSSH Ed25519 (via Montgomery Curve25519 ECDH + HKDF) & RSA-OAEP-SHA256.
* **Memory Protection:** OS memory locking via `VirtualLock` (Windows) and `mlock` (POSIX) to prevent swapping to disk.
* **Data Sanitization:** Cryptographic overwrite with CSPRNG bytes and zeroes before memory release or file deletion.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more details.
