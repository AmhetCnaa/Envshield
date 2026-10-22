from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        result.scanned_files_count += 1
        for scanner in scanners:
            findings = scanner.scan_file(file_path, content)
            for finding in findings:
                result.add_finding(finding)
    except (OSError, UnicodeDecodeError):
        # Ignore binary or unreadable files quietly for now
        pass


def handle_seal(args: list[str], console: Console) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield seal",
        description="Encrypt an environment file into a secure vault (.env.enc).",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".env",
        help="Path to .env file to seal (default: .env)",
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
        help="Securely overwrite and remove the original unencrypted file after sealing.",
    )
    parsed = parser.parse_args(args)

    source_path = Path(parsed.path)
    if not source_path.is_file():
        console.print(f"[red]Error: Source file '{source_path}' does not exist.[/red]")
        sys.exit(1)

    target_path = Path(parsed.output) if parsed.output else Path(f"{source_path}.enc")

    password = os.environ.get("ENVSHIELD_KEY")
    if not password:
        try:
            password = getpass.getpass("Enter encryption password: ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Operation cancelled.[/yellow]")
            sys.exit(1)

    if not password:
        console.print("[red]Error: Password cannot be empty.[/red]")
        sys.exit(1)

    try:
        seal_file(source_path, target_path, password)
        console.print(f"[green]Successfully sealed '{source_path}' -> '{target_path}'.[/green]")
        if parsed.shred:
            shred_file(source_path)
            console.print(f"[yellow]Securely shredded original file '{source_path}'.[/yellow]")
    except (OSError, AuthError) as exc:
        console.print(f"[red]Error sealing file: {exc}[/red]")
        sys.exit(1)

    sys.exit(0)


def handle_run(args: list[str], console: Console) -> None:
    # Separate options and command
    if "--" in args:
        dash_idx = args.index("--")
        opt_args = args[:dash_idx]
        command = args[dash_idx + 1 :]
    else:
        # If '--' is not present, parse known flags
        parser = argparse.ArgumentParser(
            prog="envshield run",
            description="Run a command with decrypted secrets injected into memory.",
            add_help=False,
        )
        parser.add_argument(
            "--env-file",
            default=".env.enc",
            help="Path to encrypted environment file (default: .env.enc)",
        )
        parser.add_argument("-h", "--help", action="store_true")
        parsed_opts, command = parser.parse_known_args(args)
        if parsed_opts.help:
            full_parser = argparse.ArgumentParser(
                prog="envshield run",
                description="Run a command with decrypted secrets injected into memory.",
            )
            full_parser.add_argument(
                "--env-file",
                default=".env.enc",
                help="Path to encrypted environment file (default: .env.enc)",
            )
            full_parser.add_argument(
                "command",
                nargs=argparse.REMAINDER,
                help="Command to execute (e.g. envshield run -- python app.py)",
            )
            full_parser.print_help()
            sys.exit(0)
        opt_args = ["--env-file", parsed_opts.env_file]

    parser = argparse.ArgumentParser(
        prog="envshield run",
        description="Run a command with decrypted secrets injected into memory.",
    )
    parser.add_argument(
        "--env-file",
        default=".env.enc",
        help="Path to encrypted environment file (default: .env.enc)",
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

    password = os.environ.get("ENVSHIELD_KEY")
    if not password:
        try:
            password = getpass.getpass("Enter decryption password: ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Operation cancelled.[/yellow]")
            sys.exit(1)

    if not password:
        console.print("[red]Error: Password cannot be empty.[/red]")
        sys.exit(1)

    try:
        secrets = unseal_to_memory(env_path, password)
    except (InvalidKey, AuthError) as exc:
        console.print(f"[red]Decryption failed: {exc}[/red]")
        sys.exit(1)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Error unsealing environment file: {exc}[/red]")
        sys.exit(1)

    exit_code = execute_with_env(command, secrets)
    sys.exit(exit_code)


def handle_scan(args: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="envshield",
        description="envshield: Enterprise-grade security and environment auditing CLI.",
        epilog="Subcommands:\n  seal [PATH] [--shred]         Encrypt an environment file\n  run [--env-file FILE] -- CMD  Run a command with decrypted secrets\n",
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

    # Secret Scanning
    for file_path in files_to_scan:
        scan_file(file_path, scanners, result)

    # Env Validation if .env and .env.example are in paths (naive approach for root)
    env_files = [f for f in files_to_scan if os.path.basename(f) == '.env']
    env_example_files = [f for f in files_to_scan if os.path.basename(f) == '.env.example']

    for env_path in env_files:
        dir_name = os.path.dirname(env_path)
        example_path = os.path.join(dir_name, ".env.example")
        if example_path in env_example_files:
            try:
                with open(env_path, 'r', encoding='utf-8') as f1, open(example_path, 'r', encoding='utf-8') as f2:
                    env_findings = env_validator.validate(env_path, f1.read(), example_path, f2.read())
                    for f in env_findings:
                        result.add_finding(f)
            except OSError:
                pass

    if parsed.format == "json":
        print(format_json(result))
    elif parsed.format == "sarif":
        print(format_sarif(result))
    else:
        # Text/Rich formatting
        if result.has_issues():
            console.print(Panel(f"[red]Found {len(result.findings)} issues across {result.scanned_files_count} files.[/red]"))
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
            console.print(Panel(f"[green]Clean scan! Scanned {result.scanned_files_count} files. No issues found.[/green]"))

    if result.has_issues():
        sys.exit(1)
    else:
        sys.exit(0)


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    console = Console()

    if argv and argv[0] == "seal":
        handle_seal(argv[1:], console)
        return
    if argv and argv[0] == "run":
        handle_run(argv[1:], console)
        return
    if argv and argv[0] == "scan":
        handle_scan(argv[1:])
        return

    handle_scan(argv)


if __name__ == "__main__":
    main()
