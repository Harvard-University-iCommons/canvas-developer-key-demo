"""Tests for canvas_oauth.models.CanvasToken."""

from datetime import timedelta

import pytest
from django.contrib.auth.models import AbstractBaseUser
from django.utils import timezone

from canvas_oauth.models import CanvasToken

pytestmark = pytest.mark.django_db


def test_access_token_is_stored_encrypted(user: AbstractBaseUser) -> None:
    token = CanvasToken(
        user=user,
        canvas_user_id=123,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    token.access_token = "plain-access"
    token.refresh_token = "plain-refresh"

    assert token.encrypted_access_token
    assert token.encrypted_access_token != "plain-access"
    assert "plain-access" not in token.encrypted_access_token
    assert token.encrypted_refresh_token != "plain-refresh"
    assert "plain-refresh" not in token.encrypted_refresh_token


def test_token_properties_round_trip_through_database(canvas_token: CanvasToken) -> None:
    reloaded = CanvasToken.objects.get(pk=canvas_token.pk)
    assert reloaded.access_token == "access-1"
    assert reloaded.refresh_token == "refresh-1"
    raw = CanvasToken.objects.values_list("encrypted_access_token", flat=True).get(
        pk=canvas_token.pk
    )
    assert raw != "access-1"


def test_is_expired_false_when_well_in_future(canvas_token: CanvasToken) -> None:
    assert canvas_token.is_expired() is False


def test_is_expired_true_when_in_past(expired_token: CanvasToken) -> None:
    assert expired_token.is_expired() is True


def test_is_expired_respects_leeway(user: AbstractBaseUser) -> None:
    token = CanvasToken(
        user=user,
        canvas_user_id=123,
        expires_at=timezone.now() + timedelta(seconds=30),
    )
    # Default leeway is 60 seconds: 30 seconds from now counts as expired.
    assert token.is_expired() is True
    # With no leeway the token is still valid.
    assert token.is_expired(leeway_seconds=0) is False
    # With a generous leeway an hour-long token is treated as expired.
    token.expires_at = timezone.now() + timedelta(hours=1)
    assert token.is_expired(leeway_seconds=2 * 60 * 60) is True


def test_str_does_not_leak_token_values(canvas_token: CanvasToken) -> None:
    text = str(canvas_token)
    assert "access-1" not in text
    assert "refresh-1" not in text
    assert canvas_token.encrypted_access_token not in text
    assert "123" in text
