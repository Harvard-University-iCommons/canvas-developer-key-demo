"""Symmetric encryption helpers for Canvas tokens at rest (Fernet)."""

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _fernet() -> Fernet:
    key = getattr(settings, "TOKEN_ENCRYPTION_KEY", "")
    if not key:
        raise ImproperlyConfigured("TOKEN_ENCRYPTION_KEY is not set.")
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured("TOKEN_ENCRYPTION_KEY is not a valid Fernet key.") from exc


def encrypt(plaintext: str) -> str:
    """Encrypt a string and return the Fernet token as a str."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token (str) back to the original string."""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ImproperlyConfigured(
            "Stored token could not be decrypted with the configured TOKEN_ENCRYPTION_KEY."
        ) from exc
