from __future__ import annotations

import base64
import re
import threading
import urllib.parse
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
    Features:
      - Multi-encoding detection: masks raw, Base64-encoded, and URL-encoded forms of secrets.
      - Sliding window lookahead buffer: prevents secrets split across arbitrary read() chunk
        boundaries from leaking to stdout/stderr.
    """

    def __init__(self, secrets: dict[str, str], min_length: int = 4) -> None:
        self.min_length = min_length
        self.val_to_key: dict[str, str] = {}
        self._pending_buffer: str = ""

        # Collect secrets and their encoded variants (Base64, URL-encoded)
        for key, val in secrets.items():
            sval = str(val).strip()
            if len(sval) < self.min_length or sval.lower() in COMMON_NON_SECRETS:
                continue

            # 1. Raw secret
            if sval not in self.val_to_key:
                self.val_to_key[sval] = key

            # 2. Base64-encoded variants (standard and unpadded URL-safe)
            raw_bytes = sval.encode("utf-8")
            b64_std = base64.b64encode(raw_bytes).decode("ascii")
            b64_unpadded = b64_std.rstrip("=")
            b64_urlsafe = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")

            for encoded_variant in (b64_std, b64_unpadded, b64_urlsafe):
                if len(encoded_variant) >= self.min_length and encoded_variant not in self.val_to_key:
                    self.val_to_key[encoded_variant] = key

            # 3. URL-encoded variant (e.g. p@ssword! -> p%40ssword%21)
            url_encoded = urllib.parse.quote(sval, safe="")
            if (
                url_encoded != sval
                and len(url_encoded) >= self.min_length
                and url_encoded not in self.val_to_key
            ):
                self.val_to_key[url_encoded] = key

        # Sort values by length descending so longer matching secrets get redacted first
        sorted_vals = sorted(self.val_to_key.keys(), key=len, reverse=True)
        self.max_secret_len: int = len(sorted_vals[0]) if sorted_vals else 0

        if sorted_vals:
            escaped = [re.escape(v) for v in sorted_vals]
            self.pattern: re.Pattern[str] | None = re.compile("|".join(escaped))
        else:
            self.pattern = None

    def redact_text(self, text: str) -> str:
        """Sanitizes a complete text string or log line."""
        if not self.pattern or not text:
            return text

        def _repl(match: re.Match[str]) -> str:
            matched_val = match.group(0)
            key_name = self.val_to_key.get(matched_val, "SECRET")
            return f"[REDACTED:{key_name}]"

        return self.pattern.sub(_repl, text)

    def redact_chunk(self, chunk: str, is_eof: bool = False) -> str:
        """
        Stateful sliding-window chunk redactor.
        Handles secrets split across two consecutive read() chunks by holding back
        a lookahead tail of (max_secret_len - 1) raw characters when no newline boundary is present.
        Prevents double-redaction (nested [REDACTED:[REDACTED:KEY]]) by immediately emitting
        through the end of any completed match and only keeping unredacted raw tail characters
        in `_pending_buffer`.
        """
        if not self.pattern:
            return chunk

        combined = self._pending_buffer + chunk
        self._pending_buffer = ""

        if is_eof or not combined:
            return self.redact_text(combined)

        if combined.endswith("\n"):
            return self.redact_text(combined)

        lookahead = max(0, self.max_secret_len - 1)
        if lookahead == 0:
            return self.redact_text(combined)

        # Find all complete secret matches in `combined` on the raw text first
        out_parts: list[str] = []
        last_end = 0
        for match in self.pattern.finditer(combined):
            start, end = match.span()
            out_parts.append(combined[last_end:start])
            key_name = self.val_to_key.get(match.group(0), "SECRET")
            out_parts.append(f"[REDACTED:{key_name}]")
            last_end = end

        # `unmatched_tail` is strictly the raw suffix after the last matched secret.
        # It never contains any `[REDACTED:...]` markers, eliminating nested double-redaction!
        unmatched_tail = combined[last_end:]

        if len(unmatched_tail) > lookahead:
            safe_raw_cutoff = len(unmatched_tail) - lookahead
            out_parts.append(unmatched_tail[:safe_raw_cutoff])
            self._pending_buffer = unmatched_tail[safe_raw_cutoff:]
        else:
            self._pending_buffer = unmatched_tail

        return "".join(out_parts)

    def close(self) -> None:
        """Clears in-memory plaintext lookup tables and compiled regex patterns on exit."""
        self.val_to_key.clear()
        self.pattern = None
        self._pending_buffer = ""


    def stream_pipe(
        self,
        pipe_in: IO[str],
        pipe_out: IO[str],
        on_line: Callable[[str], None] | None = None,
    ) -> None:
        """
        Continuously reads from pipe_in, sanitizes via sliding window & line boundaries,
        and flushes to pipe_out until EOF.
        """
        try:
            for line in iter(pipe_in.readline, ""):
                sanitized = self.redact_chunk(line, is_eof=False)
                if sanitized:
                    pipe_out.write(sanitized)
                    pipe_out.flush()
                    if on_line:
                        on_line(sanitized)

            # Flush any remaining lookahead buffer at EOF
            tail = self.redact_chunk("", is_eof=True)
            if tail:
                pipe_out.write(tail)
                pipe_out.flush()
                if on_line:
                    on_line(tail)
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
