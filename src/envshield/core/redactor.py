from __future__ import annotations

import re
import threading
from typing import IO, Callable

COMMON_NON_SECRETS = {
    "true",
    "false",
    "null",
    "none",
    "undefined",
    "0",
    "1",
    "yes",
    "no",
    "dev",
    "prod",
    "test",
    "localhost",
    "127.0.0.1",
    "development",
    "production",
    "staging",
}


class SecretRedactor:
    """
    Real-time stream and string sanitizer that masks sensitive secret values.
    Replaces exposed secrets with [REDACTED:<KEY_NAME>] to prevent accidental
    leaks in stdout, stderr, stack traces, and terminal logs.
    """

    def __init__(self, secrets: dict[str, str], min_length: int = 4) -> None:
        self.min_length = min_length
        self.val_to_key: dict[str, str] = {}

        # Collect secrets worthy of redaction (avoid trivial substrings like '1', 'true')
        for key, val in secrets.items():
            sval = str(val).strip()
            if (
                len(sval) >= self.min_length
                and sval.lower() not in COMMON_NON_SECRETS
                and sval not in self.val_to_key
            ):
                self.val_to_key[sval] = key

        # Sort values by length descending so longer matching secrets get redacted first
        sorted_vals = sorted(self.val_to_key.keys(), key=len, reverse=True)
        if sorted_vals:
            escaped = [re.escape(v) for v in sorted_vals]
            self.pattern: re.Pattern[str] | None = re.compile("|".join(escaped))
        else:
            self.pattern = None

    def redact_text(self, text: str) -> str:
        """Sanitizes a single text string or log line."""
        if not self.pattern or not text:
            return text

        def _repl(match: re.Match[str]) -> str:
            matched_val = match.group(0)
            key_name = self.val_to_key.get(matched_val, "SECRET")
            return f"[REDACTED:{key_name}]"

        return self.pattern.sub(_repl, text)

    def stream_pipe(
        self,
        pipe_in: IO[str],
        pipe_out: IO[str],
        on_line: Callable[[str], None] | None = None,
    ) -> None:
        """
        Continuously reads lines from pipe_in, sanitizes them, and flushes to pipe_out.
        Runs until pipe_in reaches EOF.
        """
        try:
            for line in iter(pipe_in.readline, ""):
                sanitized = self.redact_text(line)
                pipe_out.write(sanitized)
                pipe_out.flush()
                if on_line:
                    on_line(sanitized)
        except (ValueError, OSError):
            pass
        finally:
            try:
                pipe_in.close()
            except Exception:
                pass


def sanitize_stream(
    pipe_in: IO[str],
    pipe_out: IO[str],
    redactor: SecretRedactor,
) -> threading.Thread:
    """Spawns a daemon thread to sanitize and stream output in real-time."""
    thread = threading.Thread(
        target=redactor.stream_pipe,
        args=(pipe_in, pipe_out),
        daemon=True,
    )
    thread.start()
    return thread
