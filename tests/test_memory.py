from __future__ import annotations

from envshield.core.memory import SecureBuffer, lock_memory, secure_wipe, unlock_memory


def test_lock_and_unlock_memory():
    data = bytearray(b"SENSITIVE_API_TOKEN_999")
    locked = lock_memory(data)
    assert isinstance(locked, bool)

    unlocked = unlock_memory(data)
    assert isinstance(unlocked, bool)

    # Empty data should return True
    assert lock_memory(b"") is True
    assert unlock_memory(b"") is True


def test_secure_wipe():
    buf = bytearray(b"SECRET_PASSWORD_1234")
    assert b"SECRET" in buf

    secure_wipe(buf)
    assert all(b == 0 for b in buf)
    assert len(buf) == 20


def test_secure_buffer_context_manager():
    secret_text = "DATABASE_URL=postgres://user:pass@localhost:5432/db"
    with SecureBuffer(secret_text) as sec_buf:
        assert sec_buf.to_str() == secret_text
        assert sec_buf.to_bytes() == secret_text.encode("utf-8")
        assert len(sec_buf.buffer) == len(secret_text)

    # After exit, memory should be wiped
    assert all(b == 0 for b in sec_buf.buffer)
