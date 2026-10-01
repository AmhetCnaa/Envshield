import os
import subprocess


def get_staged_files() -> list[str]:
    """Returns a list of staged files in the git repository."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        # Only return existing files (to ignore deleted files)
        return [f for f in files if os.path.isfile(f)]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def install_pre_commit_hook() -> bool:
    """Installs the envshield pre-commit hook in the local git repository."""
    git_dir_result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        capture_output=True,
        text=True
    )
    if git_dir_result.returncode != 0:
        return False
        
    git_dir = git_dir_result.stdout.strip()
    hook_path = os.path.join(git_dir, "hooks", "pre-commit")
    
    hook_script = """#!/bin/sh
# envshield pre-commit hook
echo "Running envshield pre-commit scan..."
envshield --staged --ci
if [ $? -ne 0 ]; then
    echo "envshield found issues. Commit aborted."
    exit 1
fi
exit 0
"""
    try:
        os.makedirs(os.path.dirname(hook_path), exist_ok=True)
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_script)
        
        # Make executable
        if os.name != 'nt':
            os.chmod(hook_path, 0o755)
        return True
    except OSError:
        return False
