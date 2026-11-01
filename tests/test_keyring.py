from __future__ import annotations

from unittest import mock

from envshield.core.keyring_manager import delete_key, get_key, is_keyring_available, save_key


def test_keyring_save_get_delete():
    mock_storage: dict[str, str] = {}

    def mock_set(service, name, val):
        mock_storage[f"{service}:{name}"] = val

    def mock_get(service, name):
        return mock_storage.get(f"{service}:{name}")

    def mock_del(service, name):
        key = f"{service}:{name}"
        if key in mock_storage:
            del mock_storage[key]
        else:
            raise Exception("Not found")

    with (
        mock.patch("keyring.set_password", side_effect=mock_set),
        mock.patch("keyring.get_password", side_effect=mock_get),
        mock.patch("keyring.delete_password", side_effect=mock_del),
    ):
        assert save_key("prod_vault", "secret_pass_123") is True
        assert get_key("prod_vault") == "secret_pass_123"
        assert get_key("unknown") is None
        assert delete_key("prod_vault") is True
        assert delete_key("prod_vault") is False


def test_is_keyring_available():
    res = is_keyring_available()
    assert isinstance(res, bool)
