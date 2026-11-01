from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

SERVICE_NAME = "envshield"


def is_keyring_available() -> bool:
    try:
        import keyring

        # Check if backend is not fail
        backend = keyring.get_keyring()
        return backend is not None and "fail" not in backend.__class__.__name__.lower()
    except Exception:
        return False


def save_key(name: str, key: str, service: str = SERVICE_NAME) -> bool:
    """
    Saves an encryption key or passphrase into the OS credential keyring.
    """
    try:
        import keyring

        keyring.set_password(service, name, key)
        return True
    except Exception as exc:
        logger.debug(f"Keyring save error: {exc}")
        return False


def get_key(name: str, service: str = SERVICE_NAME) -> str | None:
    """
    Retrieves an encryption key from the OS credential keyring.
    """
    try:
        import keyring

        return keyring.get_password(service, name)
    except Exception as exc:
        logger.debug(f"Keyring get error: {exc}")
        return None


def delete_key(name: str, service: str = SERVICE_NAME) -> bool:
    """
    Deletes an encryption key from the OS credential keyring.
    """
    try:
        import keyring

        keyring.delete_password(service, name)
        return True
    except Exception as exc:
        logger.debug(f"Keyring delete error: {exc}")
        return False
