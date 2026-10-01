from abc import ABC, abstractmethod

from envshield.core.models import Finding


class BaseScanner(ABC):
    """Abstract Base Class for all scanners."""
    
    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        """Scan a file's content and return any findings."""
    
    @abstractmethod
    def scan_line(self, file_path: str, line_number: int, line_content: str) -> list[Finding]:
        """Scan a single line of a file and return any findings. Used for granular scanning."""
