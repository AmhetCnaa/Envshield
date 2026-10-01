# envshield 🛡️

[![PyPI version](https://badge.fury.io/py/envshield.svg)](https://badge.fury.io/py/envshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/example/envshield/actions/workflows/ci.yml/badge.svg)](https://github.com/example/envshield/actions)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)]()

**envshield** is an enterprise-grade, open-source security and environment auditing CLI tool written in Python. It provides advanced, modular secret scanning and environment validation.

Prevent API key leaks, detect high-entropy strings, and validate environment configurations across different deployment stages, integrating seamlessly into your CI/CD pipelines and local Git hooks.

## Features ✨

- **Advanced Secret Detection Engine:** Scans for 30+ common provider secrets (AWS, GitHub, Stripe, Slack, OpenAI, PostgreSQL/Mongo URIs, Private Keys, etc.) using regex and calculates Shannon entropy for generic cryptographical keys.
- **Environment Drift Validation:** Compares `.env` and `.env.example` to detect missing variables, extraneous ones, and type mismatches.
- **Git & CI/CD Native:** Install pre-commit hooks easily, run in strict CI mode (`--ci`), and output to SARIF/JSON for GitHub Actions/GitLab CI integrations.
- **False-Positive Management:** Skip files using `.envshieldignore` or ignore inline code with `# envshield:ignore` comments.
- **Beautiful CLI UI:** Built with `rich`, providing masked secrets, actionable remediation steps, and intuitive summary tables.

## Installation 📦

```bash
pip install envshield
```

## Usage 🚀

Run `envshield` in your project root to scan the entire directory (respecting `.envshieldignore`):

```bash
envshield
```

### CLI Screenshot
![CLI Screenshot](https://via.placeholder.com/800x400.png?text=envshield+CLI+Screenshot)

### Advanced Usage

**Scan specific paths or files:**
```bash
envshield src/ config/ .env
```

**Scan only git staged files:**
```bash
envshield --staged
```

**Install the pre-commit git hook:**
```bash
envshield --install-hook
```

**CI/CD Mode (Exits with code 1 if issues found, suppresses animations):**
```bash
envshield --ci
```

**Export as JSON or SARIF:**
```bash
envshield --format json > findings.json
envshield --format sarif > findings.sarif
```

## Configuration ⚙️

Create a `.envshieldignore` file in your project root to exclude paths:
```text
tests/fixtures/*
legacy_code/*
```

## GitHub Actions Integration 🤖

Copy-paste this workflow to your repository (`.github/workflows/envshield.yml`) to automatically block PRs that contain leaked secrets or missing env vars:

```yaml
name: Security Scan - envshield

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: "3.10"
    - name: Install dependencies
      run: pip install envshield
    - name: Run envshield (SARIF output)
      run: envshield --ci --format sarif > envshield-results.sarif
      continue-on-error: true
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: envshield-results.sarif
```

## Contributing 🤝

Contributions are welcome! Please read `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

## License 📄

This project is licensed under the MIT License - see the `LICENSE` file for details.
