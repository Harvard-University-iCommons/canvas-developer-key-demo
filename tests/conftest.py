"""Shared pytest fixtures for the canvas_oauth test suite.

Environment defaults for the Django settings module live in
``config/test_settings.py``, which pytest-django loads via pyproject.toml.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser

    from canvas_oauth.models import CanvasToken

CANVAS_USER_ID = 123
CANVAS_USER_NAME = "Jane Doe"


@pytest.fixture
def user(db: None) -> AbstractBaseUser:
    """A Django user that mirrors what the OAuth callback creates for Canvas user 123."""
    user_model = get_user_model()
    instance = user_model.objects.create(
        username=f"canvas-{CANVAS_USER_ID}",
        first_name=CANVAS_USER_NAME,
    )
    instance.set_unusable_password()
    instance.save()
    return instance


def _make_token(user: AbstractBaseUser, expires_at: datetime) -> CanvasToken:
    from canvas_oauth.models import CanvasToken

    token = CanvasToken(
        user=user,
        canvas_user_id=CANVAS_USER_ID,
        canvas_user_name=CANVAS_USER_NAME,
        expires_at=expires_at,
    )
    token.access_token = "access-1"
    token.refresh_token = "refresh-1"
    token.save()
    return token


@pytest.fixture
def canvas_token(user: AbstractBaseUser) -> CanvasToken:
    """A CanvasToken for ``user`` that expires one hour from now."""
    return _make_token(user, timezone.now() + timedelta(hours=1))


@pytest.fixture
def expired_token(user: AbstractBaseUser) -> CanvasToken:
    """A CanvasToken for ``user`` that expired five minutes ago."""
    return _make_token(user, timezone.now() - timedelta(minutes=5))


@pytest.fixture
def logged_in_client(client: Client, user: AbstractBaseUser) -> Client:
    """The Django test client, already authenticated as ``user``."""
    client.force_login(user)
    return client
