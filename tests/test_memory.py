from __future__ import annotations

from envshield.core.memory import (
    ObfuscatedSecretStore,
    SecureBuffer,
    disable_core_dumps,
    lock_memory,
    secure_wipe,
    unlock_memory,
)


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


def test_disable_core_dumps():
    res = disable_core_dumps()
    assert isinstance(res, bool)


def test_obfuscated_secret_store():
    raw_secrets = {
        "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DB_PASS": "hunter2_ultra_secret",
    }
    caller_copy = dict(raw_secrets)
    with ObfuscatedSecretStore(caller_copy, clear_source=True) as store:
        # Caller dict is immediately cleared to eliminate lingering cleartext references
        assert len(caller_copy) == 0

        # Ensure raw bytes in memory are XOR-masked and do NOT equal plaintext
        cipher_buf, pad_buf = store._entries["AWS_SECRET_KEY"]
        assert cipher_buf.to_bytes() != raw_secrets["AWS_SECRET_KEY"].encode("utf-8")
        assert len(cipher_buf.buffer) == len(pad_buf.buffer)

        # Just-in-time reveal works accurately
        assert store.reveal("AWS_SECRET_KEY") == raw_secrets["AWS_SECRET_KEY"]
        assert store.reveal("DB_PASS") == raw_secrets["DB_PASS"]
        assert store.reveal("NON_EXISTENT") is None
        assert store.reveal_all() == raw_secrets

    # After context exit, all internal buffers are zero-wiped and cleared
    assert len(store._entries) == 0



