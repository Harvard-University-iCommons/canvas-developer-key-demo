"""Encrypted-at-rest storage for a user's Canvas OAuth tokens."""

from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from canvas_oauth import crypto


class CanvasToken(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="canvas_token",
    )
    canvas_user_id = models.BigIntegerField(unique=True)
    canvas_user_name = models.CharField(max_length=255, blank=True)
    encrypted_access_token = models.TextField()
    encrypted_refresh_token = models.TextField()
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Canvas token"
        verbose_name_plural = "Canvas tokens"

    def __str__(self) -> str:
        return f"CanvasToken(canvas_user_id={self.canvas_user_id})"

    __repr__ = __str__

    @property
    def access_token(self) -> str:
        return crypto.decrypt(self.encrypted_access_token)

    @access_token.setter
    def access_token(self, value: str) -> None:
        self.encrypted_access_token = crypto.encrypt(value)

    @property
    def refresh_token(self) -> str:
        return crypto.decrypt(self.encrypted_refresh_token)

    @refresh_token.setter
    def refresh_token(self, value: str) -> None:
        self.encrypted_refresh_token = crypto.encrypt(value)

    def is_expired(self, leeway_seconds: int = 60) -> bool:
        """Return True if the access token expires within ``leeway_seconds`` from now."""
        return self.expires_at <= timezone.now() + timedelta(seconds=leeway_seconds)
