"""Tests for the canvas_oauth views (home, login, callback, courses, logout)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
import responses
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.test import Client
from django.urls import reverse

from canvas_oauth.models import CanvasToken

pytestmark = pytest.mark.django_db

BASE_URL = "https://canvas.example.test"
TOKEN_URL = f"{BASE_URL}/login/oauth2/token"
COURSES_URL = f"{BASE_URL}/api/v1/courses"

TOKEN_RESPONSE = {
    "access_token": "access-1",
    "refresh_token": "refresh-1",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {"id": 123, "name": "Jane Doe", "global_id": "1000000000123"},
}


def _set_session(client: Client, **values: str) -> None:
    """Store values in the test client's session (works for anonymous clients too)."""
    session = client.session
    for key, value in values.items():
        session[key] = value
    session.save()


def _is_logged_in(client: Client) -> bool:
    return "_auth_user_id" in client.session


def _content(response) -> str:  # noqa: ANN001
    return response.content.decode()


# --------------------------------------------------------------------------- #
# home
# --------------------------------------------------------------------------- #


def test_home_anonymous_shows_sign_in_link(client: Client) -> None:
    response = client.get(reverse("canvas_oauth:home"))
    assert response.status_code == 200
    body = _content(response)
    assert reverse("canvas_oauth:login") in body
    assert "Sign in with Canvas" in body
    assert reverse("canvas_oauth:logout") not in body


def test_home_logged_in_shows_name_and_logout_form(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    response = logged_in_client.get(reverse("canvas_oauth:home"))
    assert response.status_code == 200
    body = _content(response)
    assert "Jane Doe" in body
    assert reverse("canvas_oauth:courses") in body
    assert reverse("canvas_oauth:logout") in body
    assert "csrfmiddlewaretoken" in body
    assert 'method="post"' in body.lower()
    # Never render token values.
    assert "access-1" not in body
    assert canvas_token.encrypted_access_token not in body


# --------------------------------------------------------------------------- #
# login
# --------------------------------------------------------------------------- #


def test_login_redirects_to_canvas_with_state_in_session(client: Client) -> None:
    response = client.get(reverse("canvas_oauth:login"))

    assert response.status_code == 302
    location = response["Location"]
    parts = urlsplit(location)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{BASE_URL}/login/oauth2/auth"

    query = parse_qs(parts.query)
    state = client.session["oauth_state"]
    assert state
    assert len(state) >= 32
    assert query["state"] == [state]
    assert query["client_id"] == [settings.CANVAS_CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == [settings.CANVAS_REDIRECT_URI]
    assert settings.CANVAS_CLIENT_SECRET not in location


def test_login_generates_a_fresh_state_each_time(client: Client) -> None:
    client.get(reverse("canvas_oauth:login"))
    first = client.session["oauth_state"]
    client.get(reverse("canvas_oauth:login"))
    second = client.session["oauth_state"]
    assert first != second


# --------------------------------------------------------------------------- #
# callback
# --------------------------------------------------------------------------- #


def test_callback_access_denied_returns_403(client: Client) -> None:
    _set_session(client, oauth_state="abc")
    response = client.get(
        reverse("canvas_oauth:callback"), {"error": "access_denied", "state": "abc"}
    )
    assert response.status_code == 403
    assert not _is_logged_in(client)


def test_callback_missing_state_in_session_returns_400(client: Client) -> None:
    response = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "xyz"})
    assert response.status_code == 400
    assert not _is_logged_in(client)


def test_callback_mismatched_state_returns_400(client: Client) -> None:
    _set_session(client, oauth_state="abc")
    response = client.get(reverse("canvas_oauth:callback"), {"state": "not-abc", "code": "xyz"})
    assert response.status_code == 400
    assert not _is_logged_in(client)


def test_callback_missing_state_param_returns_400(client: Client) -> None:
    _set_session(client, oauth_state="abc")
    response = client.get(reverse("canvas_oauth:callback"), {"code": "xyz"})
    assert response.status_code == 400


def test_callback_missing_code_returns_400(client: Client) -> None:
    _set_session(client, oauth_state="abc")
    response = client.get(reverse("canvas_oauth:callback"), {"state": "abc"})
    assert response.status_code == 400
    assert not _is_logged_in(client)


@responses.activate
def test_callback_happy_path_creates_user_and_token_and_logs_in(client: Client) -> None:
    responses.add(responses.POST, TOKEN_URL, json=TOKEN_RESPONSE, status=200)
    _set_session(client, oauth_state="abc")

    response = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "the-code"})

    assert response.status_code == 302
    assert response["Location"] == reverse("canvas_oauth:courses")

    # Token exchange happened with the code we were given.
    assert len(responses.calls) == 1
    body = responses.calls[0].request.body
    if isinstance(body, bytes):
        body = body.decode()
    form = parse_qs(body)
    assert form["grant_type"] == ["authorization_code"]
    assert form["code"] == ["the-code"]

    # User was created with an unusable password.
    user = get_user_model().objects.get(username="canvas-123")
    assert not user.has_usable_password()
    assert user.first_name == "Jane Doe"

    # Token stored encrypted at rest.
    token = CanvasToken.objects.get(canvas_user_id=123)
    assert token.user == user
    assert token.canvas_user_name == "Jane Doe"
    assert token.access_token == "access-1"
    assert token.refresh_token == "refresh-1"
    raw_access, raw_refresh = CanvasToken.objects.values_list(
        "encrypted_access_token", "encrypted_refresh_token"
    ).get(pk=token.pk)
    assert raw_access != "access-1"
    assert "access-1" not in raw_access
    assert raw_refresh != "refresh-1"
    assert not token.is_expired()

    # Logged in, and the state was consumed.
    assert client.session["_auth_user_id"] == str(user.pk)
    assert "oauth_state" not in client.session


@responses.activate
def test_callback_updates_existing_user_and_token(
    client: Client, user: AbstractBaseUser, canvas_token: CanvasToken
) -> None:
    fresh = dict(TOKEN_RESPONSE, access_token="access-9", refresh_token="refresh-9")
    responses.add(responses.POST, TOKEN_URL, json=fresh, status=200)
    _set_session(client, oauth_state="abc")

    response = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "c"})

    assert response.status_code == 302
    assert get_user_model().objects.filter(username="canvas-123").count() == 1
    assert CanvasToken.objects.count() == 1
    token = CanvasToken.objects.get(canvas_user_id=123)
    assert token.pk == canvas_token.pk
    assert token.user == user
    assert token.access_token == "access-9"
    assert token.refresh_token == "refresh-9"
    assert client.session["_auth_user_id"] == str(user.pk)


@responses.activate
def test_callback_token_exchange_failure_returns_502(client: Client) -> None:
    responses.add(responses.POST, TOKEN_URL, json={"error": "server_error"}, status=500)
    _set_session(client, oauth_state="abc")

    response = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "c"})

    assert response.status_code == 502
    assert not _is_logged_in(client)
    assert not CanvasToken.objects.exists()
    assert settings.CANVAS_CLIENT_SECRET not in _content(response)


@responses.activate
def test_callback_state_is_single_use(client: Client) -> None:
    responses.add(responses.POST, TOKEN_URL, json=TOKEN_RESPONSE, status=200)
    _set_session(client, oauth_state="abc")

    first = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "c"})
    assert first.status_code == 302

    second = client.get(reverse("canvas_oauth:callback"), {"state": "abc", "code": "c"})
    assert second.status_code == 400
    # No second token exchange happened.
    assert len(responses.calls) == 1


# --------------------------------------------------------------------------- #
# courses
# --------------------------------------------------------------------------- #


def test_courses_anonymous_redirects_to_login(client: Client) -> None:
    response = client.get(reverse("canvas_oauth:courses"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("canvas_oauth:login"))


@responses.activate
def test_courses_renders_course_names_and_codes(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[
            {
                "id": 1,
                "name": "Intro to Testing",
                "course_code": "TEST-101",
                "enrollments": [{"type": "student"}],
                "term": {"name": "Fall 2026"},
            },
            {
                "id": 2,
                "name": "Advanced Testing",
                "course_code": "TEST-201",
                "enrollments": [{"type": "teacher"}],
            },
        ],
        status=200,
    )

    response = logged_in_client.get(reverse("canvas_oauth:courses"))

    assert response.status_code == 200
    body = _content(response)
    assert "Intro to Testing" in body
    assert "TEST-101" in body
    assert "Advanced Testing" in body
    assert "TEST-201" in body
    assert "Fall 2026" in body
    assert "student" in body
    assert "teacher" in body
    assert "access-1" not in body

    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer access-1"
    assert parse_qs(urlsplit(request.url).query)["enrollment_state"] == ["active"]


@responses.activate
def test_courses_escapes_html_in_course_data(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[
            {"id": 1, "name": "<script>alert(1)</script>", "course_code": "X", "enrollments": []}
        ],
        status=200,
    )
    response = logged_in_client.get(reverse("canvas_oauth:courses"))
    body = _content(response)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_courses_without_canvas_token_redirects_to_login(logged_in_client: Client) -> None:
    assert not CanvasToken.objects.exists()
    response = logged_in_client.get(reverse("canvas_oauth:courses"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("canvas_oauth:login"))


@responses.activate
def test_courses_api_failure_returns_502(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    responses.add(responses.GET, COURSES_URL, json={"errors": "boom"}, status=500)
    response = logged_in_client.get(reverse("canvas_oauth:courses"))
    assert response.status_code == 502
    assert "access-1" not in _content(response)


@responses.activate
def test_courses_refreshes_expired_token_before_listing(
    logged_in_client: Client, expired_token: CanvasToken
) -> None:
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600},
        status=200,
    )
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[{"id": 1, "name": "Refreshed", "course_code": "R-1", "enrollments": []}],
        status=200,
    )

    response = logged_in_client.get(reverse("canvas_oauth:courses"))

    assert response.status_code == 200
    assert "Refreshed" in _content(response)
    assert [c.request.method for c in responses.calls] == ["POST", "GET"]
    assert responses.calls[1].request.headers["Authorization"] == "Bearer access-2"
    assert CanvasToken.objects.get(pk=expired_token.pk).access_token == "access-2"


# --------------------------------------------------------------------------- #
# logout
# --------------------------------------------------------------------------- #


def test_logout_get_not_allowed(logged_in_client: Client, canvas_token: CanvasToken) -> None:
    response = logged_in_client.get(reverse("canvas_oauth:logout"))
    assert response.status_code == 405
    assert CanvasToken.objects.filter(pk=canvas_token.pk).exists()
    assert _is_logged_in(logged_in_client)


def test_logout_anonymous_redirects_to_login(client: Client) -> None:
    response = client.post(reverse("canvas_oauth:logout"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("canvas_oauth:login"))


@responses.activate
def test_logout_post_revokes_deletes_and_logs_out(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    responses.add(responses.DELETE, TOKEN_URL, json={}, status=200)

    response = logged_in_client.post(reverse("canvas_oauth:logout"))

    assert response.status_code == 302
    assert response["Location"] == reverse("canvas_oauth:home")

    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.method == "DELETE"
    assert request.url.split("?")[0] == TOKEN_URL
    assert request.headers["Authorization"] == "Bearer access-1"

    assert not CanvasToken.objects.filter(pk=canvas_token.pk).exists()
    assert not _is_logged_in(logged_in_client)

    # Home now shows the anonymous view again.
    home = logged_in_client.get(reverse("canvas_oauth:home"))
    assert "Sign in with Canvas" in _content(home)


@responses.activate
def test_logout_still_succeeds_when_revoke_fails(
    logged_in_client: Client, canvas_token: CanvasToken
) -> None:
    responses.add(responses.DELETE, TOKEN_URL, status=500)

    response = logged_in_client.post(reverse("canvas_oauth:logout"))

    assert response.status_code == 302
    assert not CanvasToken.objects.filter(pk=canvas_token.pk).exists()
    assert not _is_logged_in(logged_in_client)


def test_logout_requires_csrf_token(user: AbstractBaseUser, canvas_token: CanvasToken) -> None:
    strict_client = Client(enforce_csrf_checks=True)
    strict_client.force_login(user)
    response = strict_client.post(reverse("canvas_oauth:logout"))
    assert response.status_code == 403
    assert CanvasToken.objects.filter(pk=canvas_token.pk).exists()


@pytest.mark.django_db
@responses.activate
def test_callback_incomplete_token_response_returns_502(client: Client) -> None:
    _set_session(client, oauth_state="abc")
    responses.add(responses.POST, TOKEN_URL, json={"access_token": "only-this"}, status=200)
    response = client.get(reverse("canvas_oauth:callback"), {"code": "abc", "state": "abc"})
    assert response.status_code == 502
    assert not CanvasToken.objects.exists()


@pytest.mark.django_db
@responses.activate
def test_courses_refresh_failure_deletes_token_and_redirects_to_login(
    logged_in_client: Client, expired_token: CanvasToken
) -> None:
    responses.add(responses.POST, TOKEN_URL, json={"error": "invalid_grant"}, status=400)
    response = logged_in_client.get(reverse("canvas_oauth:courses"))
    assert response.status_code == 302
    assert response.url == reverse("canvas_oauth:login")
    assert not CanvasToken.objects.filter(pk=expired_token.pk).exists()
