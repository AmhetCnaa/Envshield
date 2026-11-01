from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from envshield.core.diff_engine import compute_in_memory_diff, render_diff
from envshield.core.editor import edit_vault
from envshield.core.keyring_manager import delete_key, get_key, save_key
from envshield.core.models import ScanResult
from envshield.core.runner import execute_with_env
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
            console.print("[red]Error: Password cannot be empty when no recipients are specified.[/red]")
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


def handle_run(args: list[str], console: Console) -> None:
    if "--" in args:
        dash_idx = args.index("--")
        opt_args = args[:dash_idx]
        command = args[dash_idx + 1 :]
    else:
        parser = argparse.ArgumentParser(
            prog="envshield run",
            description="Run a command with decrypted secrets injected into memory.",
            add_help=False,
        )
        parser.add_argument("--env-file", default=".env.enc")
        parser.add_argument("-i", "--identity", default=None)
        parser.add_argument("--keyring-name", default=None)
        parser.add_argument("-h", "--help", action="store_true")
        parsed_opts, command = parser.parse_known_args(args)
        if parsed_opts.help:
            full_parser = argparse.ArgumentParser(
                prog="envshield run",
                description="Run a command with decrypted secrets injected into memory.",
            )
            full_parser.add_argument("--env-file", default=".env.enc")
            full_parser.add_argument("-i", "--identity", default=None)
            full_parser.add_argument("--keyring-name", default=None)
            full_parser.add_argument(
                "command",
                nargs=argparse.REMAINDER,
                help="Command to execute (e.g. envshield run -- python app.py)",
            )
            full_parser.print_help()
            sys.exit(0)
        opt_args = []
        if parsed_opts.env_file != ".env.enc":
            opt_args.extend(["--env-file", parsed_opts.env_file])
        if parsed_opts.identity:
            opt_args.extend(["--identity", parsed_opts.identity])
        if parsed_opts.keyring_name:
            opt_args.extend(["--keyring-name", parsed_opts.keyring_name])

    parser = argparse.ArgumentParser(
        prog="envshield run",
        description="Run a command with decrypted secrets injected into memory.",
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

    parsed = parser.parse_args(opt_args)

    if not command:
        console.print(
            "[red]Error: No command specified to run. Usage: envshield run [--env-file .env.enc] -- COMMAND [ARGS...][/red]"
        )
        sys.exit(1)

    env_path = Path(parsed.env_file)
    if not env_path.is_file():
        console.print(f"[red]Error: Encrypted environment file '{env_path}' not found.[/red]")
        sys.exit(1)

    password: str | None = None
    # Check if we can decrypt with identity first or if password is needed
    if not parsed.identity:
        password = resolve_password(
            keyring_name=parsed.keyring_name,
            prompt_message="Enter decryption password (press Enter to use default SSH key): ",
        )

    try:
        secrets = unseal_to_memory(env_path, password=password, identity_path=parsed.identity)
    except (InvalidKey, AuthError) as exc:
        console.print(f"[red]Decryption failed: {exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error unsealing environment file: {exc}[/red]")
        sys.exit(1)

    exit_code = execute_with_env(command, secrets)
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
    parser.add_argument("paths", nargs="*", default=["."], help="Paths to scan (directories or files).")
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files.")
    parser.add_argument("--ci", action="store_true", help="CI mode: suppress animations, exit code 1 on findings.")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format.")
    parser.add_argument("--install-hook", action="store_true", help="Install git pre-commit hook.")

    parsed = parser.parse_args(args)
    console = Console(force_terminal=not parsed.ci and parsed.format == "text")

    if parsed.install_hook:
        if install_pre_commit_hook():
            console.print("[green]Successfully installed pre-commit hook![/green]")
            sys.exit(0)
        else:
            console.print("[red]Failed to install pre-commit hook. Are you in a git repository?[/red]")
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
        if cmd == "scan":
            handle_scan(argv[1:])
            return

    handle_scan(argv)


if __name__ == "__main__":
    main()
