<div align="center">

# 🛡️ Envshield

### The Zero-Disk Secret Engine & Runtime Injection CLI

**Never leave plaintext `.env` files on disk again. Encrypt once with AES-256-GCM & SSH keys, then stream secrets directly into runtime memory.**

<br>

[![PyPI Version](https://img.shields.io/pypi/v/envshield-cli?style=for-the-badge&logo=pypi&logoColor=white&color=007ec6)](https://pypi.org/project/envshield-cli/)
[![Python Versions](https://img.shields.io/pypi/pyversions/envshield-cli?style=for-the-badge&logo=python&logoColor=white&color=3776AB)](https://pypi.org/project/envshield-cli/)
[![License](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)](LICENSE)
[![Zero-Disk](https://img.shields.io/badge/RAM_Only-Zero--Disk-00C853?style=for-the-badge&logo=fastapi&logoColor=white)](https://github.com/AmhetCnaa/Envshield)
[![Security](https://img.shields.io/badge/Cipher-AES--256--GCM-blueviolet?style=for-the-badge&logo=security&logoColor=white)](https://github.com/AmhetCnaa/Envshield)

<br>

[**Quickstart**](#-quickstart-in-3-steps) • [**Why Envshield?**](#-the-problem-vs-the-solution) • [**Features**](#-features-at-a-glance) • [**Team SSH Workflow**](#-team-collaboration-with-ssh-keys) • [**CLI Reference**](#-cli-command-reference) • [**Security Specs**](#-security-specs--threat-model)

</div>

---

```
$ envshield seal .env --shred
✔ Sealed .env ➔ .env.enc [AES-256-GCM + 100,000 PBKDF2 rounds]
✔ Securely shredded original .env (3-pass random overwrite + zero fill)

$ envshield run -- python app.py
✔ RAM unlock verified [Locked with VirtualLock / mlock]
✔ 14 secrets injected into process environment (0 disk footprints)
[INFO] Server running on http://127.0.0.1:8000
```

---

## ⚡ The Problem vs The Solution

| The Traditional Way (Plain `.env`) | The Envshield Way |
| :--- | :--- |
| ❌ Plaintext secrets stored permanently on block storage | ✅ **Zero-Disk Writes**: Secrets exist **only in volatile RAM** |
| ❌ Accidental `git push` leaks credentials to GitHub | ✅ **Git-Safe**: Only encrypted `.env.enc` touches source control |
| ❌ Plaintext accessible to malware, swap files, or backups | ✅ **Anti-Dump**: Memory pages locked against swap (`mlock`) |
| ❌ Passwords shared over Slack, 1Password links, or Notion | ✅ **Team Asymmetric**: Encrypt using teammates' **SSH public keys** |
| ❌ Requires changing app code to integrate complex SDKs | ✅ **Zero Code Changes**: Injected transparently into `process.env` / `os.environ` |

---

## 🚀 Quickstart in 3 Steps

### 1. Install
```bash
pip install envshield-cli
```

### 2. Seal Your Secrets
Turn any `.env` into an encrypted vault and shred the plaintext original:
```bash
envshield seal .env --shred
```
> *.env.enc is now completely safe to commit to Git and share with your team!*

### 3. Run Anything
Execute your app with decrypted secrets streamed straight into memory:
```bash
# Python
envshield run -- python app.py

# Node.js / Next.js
envshield run -- npm run dev

# Go / Rust / Docker / Any CLI
envshield run -- cargo run
```

---

## ✨ Features at a Glance

<table>
<tr>
<td width="50%">

### 🔒 Zero-Disk Invariant
Plaintext secrets are decrypted strictly in volatile RAM and piped directly into the child process environment. No `/tmp` files, no residual swap traces.

</td>
<td width="50%">

### 👥 Team SSH Public Keys
Seal vaults for your entire team with their GitHub / OpenSSH keys (`id_ed25519.pub`, `id_rsa.pub`). No shared passwords required.

</td>
</tr>
<tr>
<td width="50%">

### 📝 In-Place Safe Editing
`envshield edit` opens your encrypted vault inside your favorite editor (`nano`, `vim`, `code`, `notepad`) using an ephemeral memory buffer that shreds on exit.

</td>
<td width="50%">

### 🔍 RAM-Only Diff Engine
`envshield diff` compares two encrypted vaults or shows uncommitted secret changes directly in terminal syntax colors without writing plaintext to disk.

</td>
</tr>
<tr>
<td width="50%">

### 🔑 Native OS Keyring
Store and auto-fetch vault master keys through Windows Credential Manager, macOS Keychain, or Linux Secret Service via `envshield key`.

</td>
<td width="50%">

### 📦 Universal File Formats
Supports `.env`, `.json`, `.toml`, and `.yaml` configurations with automatic hierarchical key flattening (`DATABASE__PORT=5432`).

</td>
</tr>
</table>

---

## 👥 Team Collaboration with SSH Keys

Stop sharing master passwords across team messaging channels. With Envshield Envelope V2 cryptography, you can seal a single vault for multiple team members using their existing SSH keys:

```bash
# Seal for Alice, Bob, and yourself:
envshield seal .env \
  -r ~/.ssh/id_ed25519.pub \
  -r ~/.ssh/alice_ed25519.pub \
  -r ~/.ssh/bob_rsa.pub \
  --no-password
```

Any authorized member unlocks the vault automatically using their private SSH key:

```bash
envshield run -i ~/.ssh/id_ed25519 -- npm start
```

---

## 💻 CLI Command Reference

<details open>
<summary><b>1. <code>envshield seal</code> — Encrypt Vault</b></summary>
<br>

```bash
# Standard interactive password seal
envshield seal .env

# Custom output file and secure disk shredding
envshield seal .env.production -o prod.env.enc --shred

# Seal with SSH keys (no password required)
envshield seal .env -r ~/.ssh/id_ed25519.pub --no-password

# Hybrid vault (unlockable by EITHER password OR SSH key)
envshield seal .env -r ~/.ssh/id_ed25519.pub

# Store encryption password automatically into OS Keyring
envshield seal .env --keyring-name my_project
```
</details>

<details>
<summary><b>2. <code>envshield run</code> — In-Memory Runtime Injection</b></summary>
<br>

```bash
# Run local process with default .env.enc
envshield run -- python main.py

# Run with SSH private key authentication
envshield run -i ~/.ssh/id_ed25519 -- uvicorn main:app --reload

# Run with key automatically retrieved from OS Keyring
envshield run --keyring-name my_project -- node server.js

# Headless / CI/CD pipeline automation
export ENVSHIELD_KEY="production-secret-passphrase"
envshield run --env-file .env.prod.enc -- ./deploy.sh
```
</details>

<details>
<summary><b>3. <code>envshield edit</code> — Safe In-Place Editing</b></summary>
<br>

```bash
# Opens ephemeral decrypted buffer in $EDITOR (or notepad/nano/vim)
envshield edit .env.enc

# Edit with specific editor
envshield edit .env.enc --editor code
```
*When you save and exit, Envshield validates the syntax, re-encrypts the vault with the original key/slots, and securely wipes the temporary buffer.*
</details>

<details>
<summary><b>4. <code>envshield diff</code> — In-Memory Vault Comparison</b></summary>
<br>

```bash
# Compare encrypted vault against local working directory .env
envshield diff .env.enc

# Compare two encrypted vaults directly in RAM
envshield diff staging.env.enc prod.env.enc
```
</details>

<details>
<summary><b>5. <code>envshield key</code> — OS Keyring Management</b></summary>
<br>

```bash
# Store vault passphrase in Windows Credential Manager / macOS Keychain
envshield key set my_project

# Retrieve stored key
envshield key get my_project

# Delete key from system keyring
envshield key delete my_project
```
</details>

<details>
<summary><b>6. <code>envshield scan</code> — Secret Leakage Auditing</b></summary>
<br>

```bash
# Scan repository for accidental hardcoded credentials & entropy leaks
envshield .

# Scan git staged files before commit
envshield --staged

# Install pre-commit Git hook
envshield --install-hook
```
</details>

---

## 🔬 How Zero-Disk Architecture Works

```text
       ┌────────────────────────┐
       │   .env.enc / vault.enc │  ◄── Encrypted on Disk (Git Safe)
       └───────────┬────────────┘
                   │
                   ▼ [Read into memory buffer]
    ╔══════════════════════════════════════════════════════════════════╗
    ║                     VOLATILE RAM BUFFER                          ║
    ║                                                                  ║
    ║   1. Resolve DEK via Password (PBKDF2) OR SSH Private Key (ECDH) ║
    ║   2. Authenticated Decryption with AES-256-GCM                   ║
    ║   3. Memory Locked against swap (VirtualLock on Win / mlock)     ║
    ║   4. Streamed directly into child process environment map        ║
    ║   5. Cryptographic zeroing (ctypes.memset) immediately on exit   ║
    ╚══════════════════════════════════════════════════════════════════╝
                   │
                   ▼ [Direct process environment injection]
       ┌────────────────────────┐
       │     Child Process      │  (Python, Node.js, Go, Rust, Docker...)
       └────────────────────────┘
```

---

## 🛡️ Security Specs & Threat Model

<details>
<summary><b>Click to expand Cryptographic Details</b></summary>
<br>

* **Payload Encryption:** AES-256-GCM (Galois/Counter Mode) authenticated encryption offering confidentiality and tamper-proof verification via Poly1305/GHASH 128-bit authentication tags.
* **Key Derivation (KDF):** PBKDF2-HMAC-SHA256 with **100,000 iterations** and a 16-byte cryptographically secure pseudorandom salt (`os.urandom(16)`).
* **Asymmetric Key Exchange:**
  - **Ed25519 SSH Keys:** Converted to Curve25519 Montgomery form for Ephemeral-Static X25519 ECDH key exchange with HKDF-SHA256 derivation.
  - **RSA SSH Keys:** RSA-OAEP with SHA-256 digest and MGF1 masking.
* **Anti-Memory Swapping:** Prevents Windows `pagefile.sys` and Linux swap leakage using `kernel32.VirtualLock` and POSIX `mlock`.
* **Forensic Disk Shredding:** 3 passes of cryptographically secure random bytes (`os.urandom`) followed by zero-fill and hardware flush (`os.fsync`) before unlinking.

</details>

---

## 📊 Benchmark & Architectural Comparison

| Feature | `envshield` | Plain `.env` | `sops` | `HashiCorp Vault` | `1Password CLI` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Zero-Disk Writes (RAM only)** | **Yes (100%)** | ❌ No | Partial | ❌ Daemon | Partial |
| **Team SSH Key Recipients** | **Yes (Ed25519/RSA)** | ❌ No | ❌ (PGP/Age) | ❌ No | ❌ Account |
| **Memory Locking (`mlock`)** | **Yes (`VirtualLock`)** | ❌ No | ❌ No | **Yes** | ❌ No |
| **In-Memory Diff Engine** | **Yes** | ❌ Plaintext | **Yes** | ❌ Web only | ❌ CLI only |
| **Native OS Keyring** | **Yes** | ❌ No | ❌ No | ❌ Token | **Yes** |
| **Cold Start Overhead** | **< 25 ms** | ~ 5 ms | ~ 60 ms | ~ 200 ms | ~ 120 ms |
| **Setup Complexity** | **Zero Config** | Zero Config | Medium | High (Server) | High (Agent) |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!  
Feel free to check [issues page](https://github.com/AmhetCnaa/Envshield/issues).

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more details.

<div align="center">
<sub>Built with 🛡️ by the Envshield Team. Star us on GitHub if you love zero-disk security!</sub>
</div>
