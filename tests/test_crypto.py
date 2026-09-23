"""Tests for canvas_oauth.crypto."""

import pytest
from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from pytest_django.fixtures import Settings

from canvas_oauth import crypto


def test_round_trip() -> None:
    plaintext = "super-secret-access-token"
    assert crypto.decrypt(crypto.encrypt(plaintext)) == plaintext


def test_ciphertext_differs_from_plaintext() -> None:
    plaintext = "super-secret-access-token"
    ciphertext = crypto.encrypt(plaintext)
    assert isinstance(ciphertext, str)
    assert ciphertext != plaintext
    assert plaintext not in ciphertext


def test_two_encryptions_of_same_plaintext_differ() -> None:
    plaintext = "same-input"
    assert crypto.encrypt(plaintext) != crypto.encrypt(plaintext)


def test_decrypt_garbage_raises() -> None:
    with pytest.raises(Exception):  # noqa: B017 - any failure is acceptable, but it must not return
        crypto.decrypt("this is not a fernet token")


def test_decrypt_with_wrong_key_raises(settings: Settings) -> None:
    ciphertext = crypto.encrypt("hello")
    settings.TOKEN_ENCRYPTION_KEY = Fernet.generate_key().decode()
    with pytest.raises(Exception):  # noqa: B017
        crypto.decrypt(ciphertext)


@pytest.mark.parametrize("bad_key", ["", None, "not-a-valid-fernet-key"])
def test_missing_or_invalid_key_raises_improperly_configured(
    settings: Settings, bad_key: str | None
) -> None:
    settings.TOKEN_ENCRYPTION_KEY = bad_key
    with pytest.raises(ImproperlyConfigured):
        crypto.encrypt("hello")
