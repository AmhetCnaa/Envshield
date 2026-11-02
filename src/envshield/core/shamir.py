from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from typing import Any

from envshield.core.memory import secure_wipe

# Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1 (0x11B / 283)
POLYNOMIAL: int = 0x11B

# Precompute GF(256) Log and Exp tables using generator 3
_EXP: list[int] = [0] * 512
_LOG: list[int] = [0] * 256


def _init_gf_tables() -> None:
    def _gf_mul_raw(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= POLYNOMIAL & 0xFF
            b >>= 1
        return p

    x = 1
    for i in range(255):
        _EXP[i] = x
        _EXP[i + 255] = x
        _LOG[x] = i
        x = _gf_mul_raw(x, 3)


_init_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a: int, b: int) -> int:
    """Division in GF(256). Raises ZeroDivisionError if b == 0."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _compute_checksum(threshold: int, index: int, hex_bytes: str) -> str:
    """Generates an 8-character verification tag for typos/tampering."""
    data = f"{threshold}:{index}:{hex_bytes}".encode()
    return hashlib.sha256(data).hexdigest()[:8]


def split_secret(secret: bytes | bytearray, threshold: int, shares: int) -> list[str]:
    """
    Splits a secret (e.g. 32-byte DEK) into N shares using Shamir's Secret Sharing over GF(2^8),
    requiring at least M (threshold) shares to reconstruct.

    Constraints:
      2 <= threshold <= shares <= 255
      len(secret) >= 1

    Returns a list of N formatted share strings:
      envshield-share-v1-<threshold>-<index>-<hex_bytes>-<checksum>
    """
    if not secret:
        raise ValueError("Secret cannot be empty.")
    if threshold < 2:
        raise ValueError(f"Threshold must be at least 2 (got {threshold}).")
    if shares < threshold:
        raise ValueError(f"Total shares ({shares}) cannot be less than threshold ({threshold}).")
    if shares > 255:
        raise ValueError(f"Maximum shares in GF(256) is 255 (got {shares}).")

    secret_len = len(secret)
    # Output share bytearrays: index 1 to shares
    raw_shares: list[bytearray] = [bytearray(secret_len) for _ in range(shares)]

    # Process each secret byte independently
    for byte_idx in range(secret_len):
        s_byte = secret[byte_idx]
        # Generate random coefficients a1, a2, ... a_{k-1}
        # a0 is the secret byte
        rand_bytes = bytearray(os.urandom(threshold - 1))
        coeffs = [s_byte] + list(rand_bytes)

        try:
            # Evaluate polynomial for x in 1..shares using Horner's rule
            for x in range(1, shares + 1):
                res = 0
                for c in reversed(coeffs):
                    res = (_gf_mul(res, x) if res != 0 else 0) ^ c
                raw_shares[x - 1][byte_idx] = res
        finally:
            secure_wipe(rand_bytes)

    # Format output strings
    share_strings: list[str] = []
    for idx in range(1, shares + 1):
        hex_data = raw_shares[idx - 1].hex()
        checksum = _compute_checksum(threshold, idx, hex_data)
        share_str = f"envshield-share-v1-{threshold}-{idx}-{hex_data}-{checksum}"
        share_strings.append(share_str)

    # Wipe raw share bytearrays
    for s_buf in raw_shares:
        secure_wipe(s_buf)

    return share_strings


def recover_secret(shares: Sequence[str]) -> bytearray:
    """
    Reconstructs the original secret from a collection of Shamir shares using
    Lagrange interpolation evaluated at x = 0 over GF(2^8).

    Validates:
      - Share string prefix and format
      - Checksum integrity
      - Consistent threshold across all shares
      - Minimum threshold count satisfied
      - No duplicate shares (unique x-coordinates)

    Returns mutable bytearray containing the recovered secret.
    """
    if not shares:
        raise ValueError("No shares provided for secret recovery.")

    parsed_shares: list[dict[str, Any]] = []
    seen_indices: set[int] = set()
    expected_threshold: int | None = None
    expected_length: int | None = None

    for s in shares:
        cleaned = s.strip()
        if not cleaned:
            continue
        if not cleaned.startswith("envshield-share-v1-"):
            raise ValueError(f"Invalid share header prefix: '{cleaned[:25]}...'")

        parts = cleaned.split("-")
        if len(parts) != 7:
            raise ValueError(f"Malformed share structure (expected 7 hyphen-separated tokens, got {len(parts)}).")

        try:
            threshold = int(parts[3])
            index = int(parts[4])
            hex_data = parts[5]
            checksum = parts[6]
        except ValueError as exc:
            raise ValueError(f"Invalid numeric token in share: {exc}") from exc

        if not (1 <= index <= 255):
            raise ValueError(f"Invalid share index {index} (must be between 1 and 255).")

        expected_chk = _compute_checksum(threshold, index, hex_data)
        if checksum != expected_chk:
            raise ValueError(f"Share checksum verification failed for share #{index}.")

        if expected_threshold is None:
            expected_threshold = threshold
        elif threshold != expected_threshold:
            raise ValueError(
                f"Conflicting thresholds detected across shares ({expected_threshold} vs {threshold})."
            )

        try:
            share_bytes = bytes.fromhex(hex_data)
        except ValueError as exc:
            raise ValueError(f"Invalid hex payload in share #{index}: {exc}") from exc

        if expected_length is None:
            expected_length = len(share_bytes)
        elif len(share_bytes) != expected_length:
            raise ValueError("Inconsistent share lengths detected.")

        if index in seen_indices:
            raise ValueError(f"Duplicate share #{index} provided. All shares must be distinct.")
        seen_indices.add(index)

        parsed_shares.append({"x": index, "y": share_bytes})

    assert expected_threshold is not None
    assert expected_length is not None

    if len(parsed_shares) < expected_threshold:
        raise ValueError(
            f"Insufficient shares provided: need at least {expected_threshold}, but got {len(parsed_shares)}."
        )

    # Use first `expected_threshold` shares
    selected = parsed_shares[:expected_threshold]
    k = expected_threshold
    x_coords = [s["x"] for s in selected]

    recovered = bytearray(expected_length)

    # Lagrange interpolation for each byte at x = 0
    for byte_idx in range(expected_length):
        y_coords = [s["y"][byte_idx] for s in selected]
        secret_byte = 0
        for j in range(k):
            xj = x_coords[j]
            yj = y_coords[j]
            weight = 1
            for m in range(k):
                if m != j:
                    xm = x_coords[m]
                    denom = xj ^ xm
                    weight = _gf_mul(weight, _gf_div(xm, denom))
            secret_byte ^= _gf_mul(yj, weight)
        recovered[byte_idx] = secret_byte

    return recovered
