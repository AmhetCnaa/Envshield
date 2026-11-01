from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from envshield.core.audit import read_audit_entries, record_audit_event, verify_audit_chain
from envshield.core.decoy import load_decoy_secrets, trigger_canary_alert
from envshield.core.diff_engine import compute_in_memory_diff, render_diff
from envshield.core.docker_bridge import execute_docker_with_secrets
from envshield.core.editor import edit_vault
from envshield.core.git_hook import install_hook, run_pre_commit_scan, uninstall_hook
from envshield.core.keyring_manager import delete_key, get_key, save_key
from envshield.core.models import ScanResult
from envshield.core.profiles import detect_git_branch_profile
from envshield.core.runner import execute_with_env
from envshield.core.team import (
    add_team_member,
    fetch_github_keys,
    list_team_members,
    remove_team_member,
    sync_team_vaults,
)
from envshield.core.vault import AuthError, InvalidKey, seal_file, shred_file, unseal_to_memory
from envshield.scanners.entropy import EntropyScanner
from envshield.scanners.env_validator import EnvValidator
from envshield.scanners.regex import RegexScanner
from envshield.utils.formatters import format_json, format_sarif
from envshield.utils.git import get_staged_files, install_pre_commit_hook
from envshield.utils.ignore import IgnoreManager


def scan_file(file_path: str, scanners: list, result: ScanResult):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        result.scanned_files_count += 1
        for scanner in scanners:
            findings = scanner.scan_file(file_path, content)
            for finding in findings:
                result.add_finding(finding)
    except (OSError, UnicodeDecodeError):
        pass


def resolve_password(
    keyring_name: str | None = None, prompt_message: str = "Enter password: "
) -> str | None:
    """Resolves password in priority: 1) ENVSHIELD_KEY env var, 2) OS Keyring, 3) Terminal prompt."""
    if os.environ.get("ENVSHIELD_KEY"):
        return os.environ.get("ENVSHIELD_KEY")

    if keyring_name:
        saved = get_key(keyring_name)
        if saved:
            return saved

    try:
        entered = getpass.getpass(prompt_message)
        return entered if entered else None
    except (KeyboardInterrupt, EOFError):
        return None


def handle_seal(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield seal",
        description="Encrypt an environment or secret file into a secure vault (.env.enc).",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".env",
        help="Path to file to seal (default: .env)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Target encrypted file path (default: <path>.enc)",
    )
    parser.add_argument(
        "--shred",
        action="store_true",
        help="Securely overwrite and remove original unencrypted file after sealing.",
    )
    parser.add_argument(
        "--recipient",
        "-r",
        action="append",
        dest="recipients",
        default=[],
        help="Recipient SSH public key (e.g. ~/.ssh/id_ed25519.pub or 'ssh-ed25519 ...'). Can be repeated.",
    )
    parser.add_argument(
        "--no-password",
        action="store_true",
        help="Skip password encryption slot when recipients are specified.",
    )
    parser.add_argument(
        "--format",
        default="auto",
        choices=["auto", "env", "json", "toml", "yaml"],
        help="Secret payload format (default: auto)",
    )
    parser.add_argument(
        "--keyring-name",
        default=None,
        help="Save the encryption password to OS keyring under this name.",
    )

    parsed = parser.parse_args(args)
    source_path = Path(parsed.path)
    if not source_path.is_file():
        console.print(f"[red]Error: Source file '{source_path}' does not exist.[/red]")
        sys.exit(1)

    target_path = Path(parsed.output) if parsed.output else Path(f"{source_path}.enc")

    password: str | None = None
    if not parsed.no_password or not parsed.recipients:
        password = resolve_password(
            keyring_name=parsed.keyring_name,
            prompt_message="Enter encryption password: ",
        )
        if not password and not parsed.recipients:
            console.print(
                "[red]Error: Password cannot be empty when no recipients are specified.[/red]"
            )
            sys.exit(1)

    if password and parsed.keyring_name and save_key(parsed.keyring_name, password):
        console.print(f"[green]Key saved to OS keyring under '{parsed.keyring_name}'.[/green]")

    try:
        seal_file(
            source_path,
            target_path,
            password=password,
            recipients=parsed.recipients if parsed.recipients else None,
            format_type=parsed.format,
        )
        console.print(f"[green]Successfully sealed '{source_path}' -> '{target_path}'.[/green]")
        if parsed.shred:
            shred_file(source_path)
            console.print(f"[yellow]Securely shredded original file '{source_path}'.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Error sealing file: {exc}[/red]")
        sys.exit(1)

    sys.exit(0)


def _build_run_parser(add_help: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envshield run",
        description="Run a command with decrypted secrets injected into memory.",
        add_help=add_help,
    )
    parser.add_argument(
        "--env-file",
        default=".env.enc",
        help="Path to encrypted environment file (default: .env.enc)",
    )
    parser.add_argument(
        "-i",
        "--identity",
        default=None,
        help="Path to SSH private key for recipient vault decryption.",
    )
    parser.add_argument(
        "--keyring-name",
        default=None,
        help="Lookup password from OS keyring under this name.",
    )
    parser.add_argument(
        "-p",
        "--profile",
        "--env",
        dest="profile",
        default=None,
        help="Environment profile section to load (e.g. production, staging).",
    )
    parser.add_argument(
        "--auto-branch",
        action="store_true",
        help="Automatically detect and select profile matching current Git branch.",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable real-time live terminal output secret masking/redaction.",
    )
    parser.add_argument(
        "-t",
        "--pty",
        action="store_true",
        help="Allocate a pseudo-terminal (PTY) for interactive programs (e.g. bash, psql, vim).",
    )
    parser.add_argument(
        "--no-interpolate",
        action="store_true",
        help="Disable dynamic ${VAR} and ${VAR:-default} interpolation in memory.",
    )
    parser.add_argument(
        "--enable-decoy",
        action="store_true",
        help="Inject decoy/canary environment if authentication fails.",
    )
    parser.add_argument(
        "--decoy-file",
        default=None,
        help="Path to custom decoy environment file for canary trap.",
    )
    parser.add_argument(
        "--alert-webhook",
        default=None,
        help="Webhook URL to notify upon unauthorized intrusion / decoy activation.",
    )
    return parser


def handle_run(args: list[str], console: Console) -> None:
    run_parser = _build_run_parser(add_help=True)
    if "--" in args:
        dash_idx = args.index("--")
        opt_args = args[:dash_idx]
        command = args[dash_idx + 1 :]
        parsed = run_parser.parse_args(opt_args)
    else:
        helper_parser = _build_run_parser(add_help=False)
        helper_parser.add_argument("-h", "--help", action="store_true")
        parsed_opts, command = helper_parser.parse_known_args(args)
        if parsed_opts.help:
            run_parser.print_help()
            sys.exit(0)
        parsed = parsed_opts

    if not command:
        console.print(
            "[red]Error: No command specified to run. Usage: envshield run [--env-file .env.enc] -- COMMAND [ARGS...][/red]"
        )
        sys.exit(1)

    env_path = Path(parsed.env_file)
    if not env_path.is_file():
        console.print(f"[red]Error: Encrypted environment file '{env_path}' not found.[/red]")
        sys.exit(1)

    selected_profile = parsed.profile
    if parsed.auto_branch and not selected_profile:
        selected_profile = detect_git_branch_profile()
        console.print(f"[dim]Git branch profile detected: '[cyan]{selected_profile}[/cyan]'[/dim]")

    password: str | None = None
    if not parsed.identity:
        password = resolve_password(
            keyring_name=parsed.keyring_name,
            prompt_message="Enter decryption password (press Enter to use default SSH key): ",
        )

    try:
        secrets = unseal_to_memory(
            env_path,
            password=password,
            identity_path=parsed.identity,
            profile=selected_profile,
            interpolate=not parsed.no_interpolate,
        )
    except (InvalidKey, AuthError) as exc:
        if parsed.enable_decoy or os.environ.get("ENVSHIELD_DECOY_ENABLED"):
            console.print(
                "[dim yellow]Warning: Access restricted. Entering isolated sandbox environment...[/dim yellow]"
            )
            trigger_canary_alert(
                env_path,
                webhook_url=parsed.alert_webhook,
                details={"reason": "auth_failure", "command": command},
            )
            secrets = load_decoy_secrets(parsed.decoy_file)
        else:
            console.print(f"[red]Decryption failed: {exc}[/red]")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error unsealing environment file: {exc}[/red]")
        sys.exit(1)

    record_audit_event(
        action="RUN",
        target_path=env_path,
        key_id="session",
        details={"command": command, "profile": selected_profile},
    )

    exit_code = execute_with_env(
        command,
        secrets,
        redact=not parsed.no_redact,
        pty=parsed.pty,
    )
    sys.exit(exit_code)


def handle_edit(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield edit",
        description="Safely edit an encrypted vault in-place in memory.",
    )
    parser.add_argument("path", nargs="?", default=".env.enc", help="Vault file to edit.")
    parser.add_argument("-i", "--identity", default=None, help="SSH private key.")
    parser.add_argument("--editor", default=None, help="Custom editor command.")
    parser.add_argument("--keyring-name", default=None, help="Keyring name.")

    parsed = parser.parse_args(args)
    vault_path = Path(parsed.path)
    if not vault_path.is_file():
        console.print(f"[red]Error: Vault '{vault_path}' does not exist.[/red]")
        sys.exit(1)

    password = resolve_password(
        keyring_name=parsed.keyring_name,
        prompt_message="Enter vault password: ",
    )

    try:
        modified = edit_vault(
            vault_path,
            password=password,
            identity_path=parsed.identity,
            editor=parsed.editor,
        )
        if modified:
            console.print(f"[green]Successfully updated vault '{vault_path}'.[/green]")
        else:
            console.print("[yellow]No changes saved.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Edit failed: {exc}[/red]")
        sys.exit(1)

    sys.exit(0)


def handle_diff(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield diff",
        description="View in-memory diff of encrypted vaults without writing plaintext to disk.",
    )
    parser.add_argument("target_a", help="First file (.env or .env.enc).")
    parser.add_argument("target_b", nargs="?", default=None, help="Second file (optional).")
    parser.add_argument("-i", "--identity", default=None, help="SSH private key.")
    parser.add_argument("--keyring-name", default=None, help="Keyring name.")

    parsed = parser.parse_args(args)
    password = resolve_password(
        keyring_name=parsed.keyring_name,
        prompt_message="Enter decryption password: ",
    )

    try:
        diff_lines = compute_in_memory_diff(
            parsed.target_a,
            parsed.target_b,
            password_a=password,
            password_b=password,
            identity_path=parsed.identity,
        )
        render_diff(diff_lines, console=console)
    except Exception as exc:
        console.print(f"[red]Diff error: {exc}[/red]")
        sys.exit(1)

    sys.exit(0)


def handle_key(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield key",
        description="Manage encryption keys in the operating system secure keyring.",
    )
    sub = parser.add_subparsers(dest="action")

    set_p = sub.add_parser("set", help="Save a key to the OS keyring.")
    set_p.add_argument("name", help="Name/identifier for the key.")

    get_p = sub.add_parser("get", help="Retrieve a key from the OS keyring.")
    get_p.add_argument("name", help="Name/identifier for the key.")
    get_p.add_argument("--show", action="store_true", help="Print raw key instead of masked.")

    del_p = sub.add_parser("delete", help="Delete a key from the OS keyring.")
    del_p.add_argument("name", help="Name/identifier for the key.")

    parsed = parser.parse_args(args)

    if parsed.action == "set":
        try:
            val = getpass.getpass(f"Enter key to store for '{parsed.name}': ")
        except (KeyboardInterrupt, EOFError):
            sys.exit(1)
        if not val:
            console.print("[red]Error: Key cannot be empty.[/red]")
            sys.exit(1)
        if save_key(parsed.name, val):
            console.print(f"[green]Key '{parsed.name}' securely stored in OS keyring.[/green]")
        else:
            console.print("[red]Failed to store key in OS keyring.[/red]")
            sys.exit(1)

    elif parsed.action == "get":
        val = get_key(parsed.name)
        if val is None:
            console.print(f"[yellow]Key '{parsed.name}' not found in OS keyring.[/yellow]")
            sys.exit(1)
        if parsed.show:
            console.print(val)
        else:
            masked = val[:2] + "*" * (max(len(val) - 4, 3)) + val[-2:] if len(val) >= 4 else "***"
            console.print(f"Key '{parsed.name}': [bold]{masked}[/bold]")

    elif parsed.action == "delete":
        if delete_key(parsed.name):
            console.print(f"[green]Key '{parsed.name}' deleted from OS keyring.[/green]")
        else:
            console.print(f"[red]Failed to delete key '{parsed.name}' from OS keyring.[/red]")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    sys.exit(0)


def handle_audit(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield audit",
        description="Inspect and verify the cryptographic tamper-evident access log.",
    )
    subparsers = parser.add_subparsers(dest="audit_cmd")

    list_p = subparsers.add_parser("list", help="List recent audit events.")
    list_p.add_argument("--limit", "-n", type=int, default=20, help="Number of entries to display.")
    list_p.add_argument("--audit-file", default=None, help="Custom audit log path.")

    verify_p = subparsers.add_parser("verify", help="Verify cryptographic hash chain integrity.")
    verify_p.add_argument("--audit-file", default=None, help="Custom audit log path.")

    parsed = parser.parse_args(args)
    if parsed.audit_cmd == "verify":
        valid, msg = verify_audit_chain(parsed.audit_file)
        if valid:
            console.print(f"[bold green]✓ {msg}[/bold green]")
            sys.exit(0)
        else:
            console.print(f"[bold red]✗ Integrity Failure: {msg}[/bold red]")
            sys.exit(1)

    # Default to list
    audit_file = getattr(parsed, "audit_file", None)
    entries = read_audit_entries(audit_file)
    if not entries:
        console.print("[dim]No audit log entries recorded yet.[/dim]")
        sys.exit(0)

    limit = getattr(parsed, "limit", 20)
    entries = entries[-limit:]

    table = Table(
        title="[bold cyan]EnvShield Cryptographic Audit Trail[/bold cyan]", show_header=True
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Timestamp (UTC)", style="cyan")
    table.add_column("Action", style="bold")
    table.add_column("Target", style="magenta")
    table.add_column("User@Host", style="green")
    table.add_column("Key Fingerprint", style="yellow")
    table.add_column("Chain Link", style="dim")

    for e in entries:
        action_name = str(e.get("action", ""))
        action_style = (
            "green"
            if action_name in ("RUN", "SEAL")
            else ("red" if "DECOY" in action_name else "blue")
        )
        table.add_row(
            str(e.get("index", "")),
            str(e.get("timestamp", ""))[:19].replace("T", " "),
            f"[{action_style}]{action_name}[/{action_style}]",
            str(Path(e.get("target_file", "")).name),
            f"{e.get('user', '')}@{e.get('hostname', '')[:10]}",
            str(e.get("key_fingerprint", ""))[:8],
            str(e.get("entry_hash", ""))[:8] + "...",
        )

    console.print(table)
    sys.exit(0)


def handle_hook(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield hook",
        description="Manage Git self-healing pre-commit hooks to block and auto-seal secrets.",
    )
    subparsers = parser.add_subparsers(dest="hook_cmd")

    install_p = subparsers.add_parser(
        "install", help="Install self-healing pre-commit hook in current repo."
    )
    install_p.add_argument(
        "--force", "-f", action="store_true", help="Overwrite existing hook if present."
    )

    subparsers.add_parser("uninstall", help="Remove pre-commit hook.")

    run_p = subparsers.add_parser("run", help="Run pre-commit protection scan.")
    run_p.add_argument("--interactive", action="store_true", default=sys.stdin.isatty())
    run_p.add_argument("--non-interactive", action="store_false", dest="interactive")

    parsed = parser.parse_args(args)
    if parsed.hook_cmd == "install":
        success, msg = install_hook(force=parsed.force)
        color = "green" if success else "red"
        console.print(f"[{color}]{msg}[/{color}]")
        sys.exit(0 if success else 1)

    if parsed.hook_cmd == "uninstall":
        success, msg = uninstall_hook()
        color = "green" if success else "yellow"
        console.print(f"[{color}]{msg}[/{color}]")
        sys.exit(0 if success else 1)

    if parsed.hook_cmd == "run":
        exit_code = run_pre_commit_scan(interactive=parsed.interactive, console=console)
        sys.exit(exit_code)

    parser.print_help()
    sys.exit(0)


def handle_team(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield team",
        description="Manage team recipient public keys and automatically re-seal vaults.",
    )
    subparsers = parser.add_subparsers(dest="team_cmd")

    subparsers.add_parser("list", help="List all registered team members and keys.")

    add_p = subparsers.add_parser(
        "add", help="Add a team member using their GitHub username or SSH public key."
    )
    add_p.add_argument("name", help="Identifier or name for the team member (e.g. ahmet).")
    add_p.add_argument(
        "--github",
        nargs="?",
        const=True,
        default=None,
        help="Fetch public SSH keys from GitHub. If no username specified, uses <name>.",
    )
    add_p.add_argument(
        "--key",
        "-k",
        action="append",
        dest="keys",
        default=[],
        help="Public key string or path to .pub file. Can be specified multiple times.",
    )
    add_p.add_argument(
        "--no-sync",
        action="store_true",
        help="Do not automatically re-seal repository vaults after adding.",
    )
    add_p.add_argument(
        "-i", "--identity", default=None, help="SSH private key to authorize re-sealing."
    )
    add_p.add_argument(
        "--keyring-name", default=None, help="Keyring password lookup for re-sealing."
    )

    remove_p = subparsers.add_parser("remove", help="Remove a team member and revoke access.")
    remove_p.add_argument("name", help="Name of the team member to remove.")
    remove_p.add_argument(
        "--no-sync",
        action="store_true",
        help="Do not automatically re-seal repository vaults after removing.",
    )
    remove_p.add_argument(
        "-i", "--identity", default=None, help="SSH private key to authorize re-sealing."
    )
    remove_p.add_argument(
        "--keyring-name", default=None, help="Keyring password lookup for re-sealing."
    )

    sync_p = subparsers.add_parser(
        "sync", help="Re-seal all repository vaults for the current team recipients."
    )
    sync_p.add_argument(
        "-i", "--identity", default=None, help="SSH private key to authorize unsealing."
    )
    sync_p.add_argument(
        "--keyring-name", default=None, help="Keyring password lookup for re-sealing."
    )

    parsed = parser.parse_args(args)

    if parsed.team_cmd == "list":
        members = list_team_members()
        if not members:
            console.print(
                "[dim]No team members configured yet. Add members with: envshield team add <name> --github[/dim]"
            )
            sys.exit(0)

        table = Table(title="[bold cyan]EnvShield Team Recipients[/bold cyan]", show_header=True)
        table.add_column("Member", style="bold green")
        table.add_column("Source", style="cyan")
        table.add_column("Key Types", style="yellow")
        table.add_column("Key Fingerprints", style="magenta")
        table.add_column("Added (UTC)", style="dim")

        for m in members:
            fps = ", ".join(m.get("fingerprints", []))
            types = ", ".join(m.get("key_types", []))
            added = str(m.get("added_at", ""))[:10]
            table.add_row(m.get("name", ""), m.get("source", "manual"), types, fps, added)

        console.print(table)
        sys.exit(0)

    if parsed.team_cmd == "add":
        keys = list(parsed.keys)
        source = "manual"

        if parsed.github is not None:
            gh_user = parsed.name if parsed.github is True else str(parsed.github)
            source = f"github:{gh_user}"
            console.print(f"[cyan]Fetching public SSH keys from GitHub for '{gh_user}'...[/cyan]")
            try:
                gh_keys = fetch_github_keys(gh_user)
                keys.extend(gh_keys)
                console.print(f"[green]✓ Found {len(gh_keys)} compatible key(s) on GitHub.[/green]")
            except Exception as exc:
                console.print(f"[red]Error fetching GitHub keys: {exc}[/red]")
                sys.exit(1)

        if not keys:
            console.print(
                "[red]Error: No keys provided. Specify --github or --key <path_to_pub_key>.[/red]"
            )
            sys.exit(1)

        try:
            add_team_member(parsed.name, keys, source=source)
            console.print(
                f"[bold green]✓ Added team member '{parsed.name}' with {len(keys)} key(s).[/bold green]"
            )
        except Exception as exc:
            console.print(f"[red]Error adding member: {exc}[/red]")
            sys.exit(1)

        if not parsed.no_sync:
            console.print(
                "\n[bold cyan]Automatically syncing repository vaults with updated team recipients...[/bold cyan]"
            )
            password = resolve_password(
                keyring_name=parsed.keyring_name,
                prompt_message="Enter password to authorize re-sealing (or press Enter if using SSH key): ",
            )
            try:
                results = sync_team_vaults(password=password, identity_path=parsed.identity)
                if not results:
                    console.print(
                        "[yellow]Notice: No .enc vaults found in project to re-seal.[/yellow]"
                    )
                for r in results:
                    if r["success"]:
                        console.print(
                            f"  [green]✓ Re-sealed {r['vault']} for {r['recipients_count']} team recipient(s).[/green]"
                        )
                    else:
                        console.print(
                            f"  [red]✗ Failed to re-seal {r['vault']}: {r.get('error')}[/red]"
                        )
            except Exception as exc:
                console.print(f"[red]Sync failed: {exc}[/red]")
                sys.exit(1)

        sys.exit(0)

    if parsed.team_cmd == "remove":
        if remove_team_member(parsed.name):
            console.print(f"[bold green]✓ Removed team member '{parsed.name}'.[/bold green]")
        else:
            console.print(f"[yellow]Member '{parsed.name}' not found in team config.[/yellow]")
            sys.exit(1)

        if not parsed.no_sync:
            console.print("\n[bold cyan]Re-sealing vaults to revoke access...[/bold cyan]")
            password = resolve_password(
                keyring_name=parsed.keyring_name,
                prompt_message="Enter password to authorize re-sealing (or press Enter if using SSH key): ",
            )
            try:
                results = sync_team_vaults(password=password, identity_path=parsed.identity)
                for r in results:
                    if r["success"]:
                        console.print(
                            f"  [green]✓ Re-sealed {r['vault']} (access revoked for '{parsed.name}').[/green]"
                        )
                    else:
                        console.print(
                            f"  [red]✗ Failed to re-seal {r['vault']}: {r.get('error')}[/red]"
                        )
            except Exception as exc:
                console.print(f"[red]Sync failed: {exc}[/red]")
                sys.exit(1)

        sys.exit(0)

    if parsed.team_cmd == "sync":
        console.print(
            "[bold cyan]Syncing repository vaults with all team recipients...[/bold cyan]"
        )
        password = resolve_password(
            keyring_name=parsed.keyring_name,
            prompt_message="Enter password to authorize re-sealing (or press Enter if using SSH key): ",
        )
        try:
            results = sync_team_vaults(password=password, identity_path=parsed.identity)
            if not results:
                console.print("[yellow]No .enc vaults found in repository.[/yellow]")
            for r in results:
                if r["success"]:
                    console.print(
                        f"  [green]✓ Re-sealed {r['vault']} for {r['recipients_count']} recipient(s).[/green]"
                    )
                else:
                    console.print(
                        f"  [red]✗ Failed to re-seal {r['vault']}: {r.get('error')}[/red]"
                    )
        except Exception as exc:
            console.print(f"[red]Sync failed: {exc}[/red]")
            sys.exit(1)

        sys.exit(0)

    parser.print_help()
    sys.exit(0)


def handle_docker(args: list[str], console: Console) -> None:
    if "--" in args:
        dash_idx = args.index("--")
        opt_args = args[:dash_idx]
        docker_args = args[dash_idx + 1 :]
        parser = argparse.ArgumentParser(
            prog="envshield docker",
            description="Run Docker containers with decrypted secrets injected into memory.",
        )
        parser.add_argument("--env-file", default=".env.enc")
        parser.add_argument("-p", "--profile", "--env", dest="profile", default=None)
        parser.add_argument("--auto-branch", action="store_true")
        parser.add_argument("-i", "--identity", default=None)
        parser.add_argument("--keyring-name", default=None)
        parser.add_argument("--stealth", action="store_true")
        parser.add_argument("--no-redact", action="store_true")
        parsed = parser.parse_args(opt_args)
    else:
        parser = argparse.ArgumentParser(
            prog="envshield docker",
            description="Run Docker containers with decrypted secrets injected into memory.",
            add_help=False,
        )
        parser.add_argument("--env-file", default=".env.enc")
        parser.add_argument("-p", "--profile", "--env", dest="profile", default=None)
        parser.add_argument("--auto-branch", action="store_true")
        parser.add_argument("-i", "--identity", default=None)
        parser.add_argument("--keyring-name", default=None)
        parser.add_argument("--stealth", action="store_true")
        parser.add_argument("--no-redact", action="store_true")
        parser.add_argument("-h", "--help", action="store_true")

        parsed_opts, docker_args = parser.parse_known_args(args)
        if parsed_opts.help or not docker_args:
            full_parser = argparse.ArgumentParser(
                prog="envshield docker",
                description="Run Docker containers with decrypted secrets injected into memory.\n\n"
                "Examples:\n"
                "  envshield docker run -p 8080:80 nginx\n"
                "  envshield docker compose up -d\n"
                "  envshield docker --stealth -- run -d myapp\n",
                formatter_class=argparse.RawDescriptionHelpFormatter,
            )
            full_parser.add_argument(
                "--env-file", default=".env.enc", help="Vault file (default: .env.enc)"
            )
            full_parser.add_argument(
                "-p",
                "--profile",
                "--env",
                dest="profile",
                default=None,
                help="Environment profile.",
            )
            full_parser.add_argument(
                "--auto-branch", action="store_true", help="Auto-detect profile from Git branch."
            )
            full_parser.add_argument("-i", "--identity", default=None, help="SSH private key.")
            full_parser.add_argument("--keyring-name", default=None, help="OS keyring lookup.")
            full_parser.add_argument(
                "--stealth",
                action="store_true",
                help="Hide secrets from `docker inspect` using in-memory tmpfs mount.",
            )
            full_parser.add_argument(
                "--no-redact", action="store_true", help="Disable live stream redaction."
            )
            full_parser.add_argument(
                "docker_args",
                nargs=argparse.REMAINDER,
                help="Docker arguments (e.g. run -p 80:80 my-image)",
            )
            full_parser.print_help()
            sys.exit(0)
        parsed = parsed_opts

    if not docker_args:
        console.print(
            "[red]Error: No docker command specified. Usage: envshield docker [OPTIONS] -- COMMAND [ARGS...][/red]"
        )
        sys.exit(1)

    env_path = Path(parsed.env_file)
    if not env_path.is_file():
        console.print(f"[red]Error: Encrypted environment file '{env_path}' not found.[/red]")
        sys.exit(1)

    selected_profile = parsed.profile
    if parsed.auto_branch and not selected_profile:
        selected_profile = detect_git_branch_profile()
        console.print(f"[dim]Git branch profile detected: '[cyan]{selected_profile}[/cyan]'[/dim]")

    password: str | None = None
    if not parsed.identity:
        password = resolve_password(
            keyring_name=parsed.keyring_name,
            prompt_message="Enter decryption password for Docker run: ",
        )

    try:
        secrets = unseal_to_memory(
            env_path,
            password=password,
            identity_path=parsed.identity,
            profile=selected_profile,
        )
    except (InvalidKey, AuthError) as exc:
        console.print(f"[red]Decryption failed: {exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error unsealing environment file: {exc}[/red]")
        sys.exit(1)

    record_audit_event(
        action="DOCKER_RUN",
        target_path=env_path,
        key_id="active_docker_session",
        details={"docker_args": docker_args, "stealth": parsed.stealth},
    )

    exit_code = execute_docker_with_secrets(
        docker_args=docker_args,
        secrets=secrets,
        stealth=parsed.stealth,
        redact=not parsed.no_redact,
    )
    sys.exit(exit_code)


def handle_scan(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield",
        description="envshield: Enterprise-grade security and environment auditing CLI.",
        epilog="Subcommands:\n"
        "  seal [PATH]                 Encrypt secrets with password or SSH recipients\n"
        "  run [--env-file F] -- CMD   Run a command with decrypted secrets\n"
        "  edit [PATH]                 Safely edit encrypted vault in-place\n"
        "  diff [A] [B]                Compare encrypted vaults in RAM\n"
        "  key {set,get,delete}        Manage OS keyring credentials\n",
    )
    parser.add_argument(
        "paths", nargs="*", default=["."], help="Paths to scan (directories or files)."
    )
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files.")
    parser.add_argument(
        "--ci", action="store_true", help="CI mode: suppress animations, exit code 1 on findings."
    )
    parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text", help="Output format."
    )
    parser.add_argument("--install-hook", action="store_true", help="Install git pre-commit hook.")

    parsed = parser.parse_args(args)
    console = Console(force_terminal=not parsed.ci and parsed.format == "text")

    if parsed.install_hook:
        if install_pre_commit_hook():
            console.print("[green]Successfully installed pre-commit hook![/green]")
            sys.exit(0)
        else:
            console.print(
                "[red]Failed to install pre-commit hook. Are you in a git repository?[/red]"
            )
            sys.exit(1)

    ignore_manager = IgnoreManager(os.getcwd())
    scanners = [RegexScanner(), EntropyScanner()]
    env_validator = EnvValidator()
    result = ScanResult()

    files_to_scan = []
    if parsed.staged:
        staged = get_staged_files()
        files_to_scan = [f for f in staged if not ignore_manager.is_ignored(f)]
    else:
        for path in parsed.paths:
            if os.path.isfile(path):
                if not ignore_manager.is_ignored(path):
                    files_to_scan.append(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        if not ignore_manager.is_ignored(full_path):
                            files_to_scan.append(full_path)

    for file_path in files_to_scan:
        scan_file(file_path, scanners, result)

    env_files = [f for f in files_to_scan if os.path.basename(f) == ".env"]
    env_example_files = [f for f in files_to_scan if os.path.basename(f) == ".env.example"]

    for env_path in env_files:
        dir_name = os.path.dirname(env_path)
        example_path = os.path.join(dir_name, ".env.example")
        if example_path in env_example_files:
            try:
                with (
                    open(env_path, "r", encoding="utf-8") as f1,
                    open(example_path, "r", encoding="utf-8") as f2,
                ):
                    env_findings = env_validator.validate(
                        env_path, f1.read(), example_path, f2.read()
                    )
                    for f in env_findings:
                        result.add_finding(f)
            except OSError:
                pass

    if parsed.format == "json":
        print(format_json(result))
    elif parsed.format == "sarif":
        print(format_sarif(result))
    else:
        if result.has_issues():
            console.print(
                Panel(
                    f"[red]Found {len(result.findings)} issues across {result.scanned_files_count} files.[/red]"
                )
            )
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Severity")
            table.add_column("File:Line")
            table.add_column("Rule")
            table.add_column("Description")
            table.add_column("Remediation")

            for finding in result.findings:
                color = "red" if finding.severity.name in ("CRITICAL", "HIGH") else "yellow"
                table.add_row(
                    f"[{color}]{finding.severity.name}[/{color}]",
                    f"{finding.file_path}:{finding.line_number}",
                    finding.rule_id,
                    finding.description,
                    finding.remediation,
                )
            console.print(table)
        else:
            console.print(
                Panel(
                    f"[green]Clean scan! Scanned {result.scanned_files_count} files. No issues found.[/green]"
                )
            )

    if result.has_issues():
        sys.exit(1)
    else:
        sys.exit(0)


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    console = Console()

    if argv:
        cmd = argv[0]
        if cmd == "seal":
            handle_seal(argv[1:], console)
            return
        if cmd == "run":
            handle_run(argv[1:], console)
            return
        if cmd == "edit":
            handle_edit(argv[1:], console)
            return
        if cmd == "diff":
            handle_diff(argv[1:], console)
            return
        if cmd == "key":
            handle_key(argv[1:], console)
            return
        if cmd == "audit":
            handle_audit(argv[1:], console)
            return
        if cmd == "team":
            handle_team(argv[1:], console)
            return
        if cmd == "docker":
            handle_docker(argv[1:], console)
            return
        if cmd == "hook":
            handle_hook(argv[1:], console)
            return
        if cmd == "scan":
            handle_scan(argv[1:])
            return

    handle_scan(argv)


if __name__ == "__main__":
    main()
