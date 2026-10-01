import argparse
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from envshield.core.models import ScanResult
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

def main():
    parser = argparse.ArgumentParser(description="envshield: Enterprise-grade security and environment auditing CLI.")
    parser.add_argument("paths", nargs="*", default=["."], help="Paths to scan (directories or files).")
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files.")
    parser.add_argument("--ci", action="store_true", help="CI mode: suppress animations, exit code 1 on findings.")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format.")
    parser.add_argument("--install-hook", action="store_true", help="Install git pre-commit hook.")
    
    args = parser.parse_args()
    
    console = Console(force_terminal=not args.ci and args.format == "text")
    
    if args.install_hook:
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
    if args.staged:
        staged = get_staged_files()
        files_to_scan = [f for f in staged if not ignore_manager.is_ignored(f)]
    else:
        for path in args.paths:
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
    # We look for .env and .env.example in the scanned files list
    env_files = [f for f in files_to_scan if os.path.basename(f) == '.env']
    env_example_files = [f for f in files_to_scan if os.path.basename(f) == '.env.example']
    
    # Just validate the first pair found in the root directory for simplicity in CLI
    # In a real scenario, we might map them per directory
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
                
    if args.format == "json":
        print(format_json(result))
    elif args.format == "sarif":
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
                    finding.remediation
                )
            console.print(table)
        else:
            console.print(Panel(f"[green]Clean scan! Scanned {result.scanned_files_count} files. No issues found.[/green]"))
            
    if result.has_issues():
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
