import fnmatch
import os


class IgnoreManager:
    """Manages path exclusions based on .envshieldignore."""

    def __init__(self, project_root: str):
        self.project_root = project_root
        self.ignore_patterns: list[str] = [".git/*", ".tox/*", "__pycache__/*"]
        self._load_ignore_file()

    def _load_ignore_file(self):
        ignore_path = os.path.join(self.project_root, ".envshieldignore")
        if os.path.exists(ignore_path):
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.ignore_patterns.append(line)

    def is_ignored(self, file_path: str) -> bool:
        """Checks if a file path matches any ignore patterns."""
        rel_path = os.path.relpath(file_path, self.project_root)
        # Normalize to forward slashes for fnmatch
        rel_path = rel_path.replace(os.sep, "/")
        for pattern in self.ignore_patterns:
            if (
                fnmatch.fnmatch(rel_path, pattern)
                or fnmatch.fnmatch(rel_path, f"{pattern}/*")
                or fnmatch.fnmatch(rel_path, f"*/{pattern}/*")
                or fnmatch.fnmatch(rel_path, f"*/{pattern}")
            ):
                return True
        return False
