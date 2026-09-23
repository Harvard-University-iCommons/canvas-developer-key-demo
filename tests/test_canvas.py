"""Tests for canvas_oauth.canvas (OAuth helpers and the Canvas API client)."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import responses
from django.conf import settings
from django.utils import timezone
from pytest_django.fixtures import Settings
from responses.registries import OrderedRegistry

from canvas_oauth import canvas
from canvas_oauth.canvas import CanvasAPIError, CanvasClient, CanvasOAuthError
from canvas_oauth.models import CanvasToken

BASE_URL = "https://canvas.example.test"
TOKEN_URL = f"{BASE_URL}/login/oauth2/token"
COURSES_URL = f"{BASE_URL}/api/v1/courses"


def _form_body(call: responses.Call) -> dict[str, str]:
    """Decode a form-encoded request body into a flat dict."""
    body = call.request.body
    if isinstance(body, bytes):
        body = body.decode()
    parsed = parse_qs(body or "", keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items()}


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


# --------------------------------------------------------------------------- #
# build_authorize_url
# --------------------------------------------------------------------------- #


def test_build_authorize_url_contains_required_params(settings: Settings) -> None:
    settings.CANVAS_SCOPES = "url:GET|/api/v1/courses"
    url = canvas.build_authorize_url("state-abc")

    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{BASE_URL}/login/oauth2/auth"

    query = _query(url)
    assert query["client_id"] == [settings.CANVAS_CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == [settings.CANVAS_REDIRECT_URI]
    assert query["state"] == ["state-abc"]
    assert query["scope"] == ["url:GET|/api/v1/courses"]


def test_build_authorize_url_omits_scope_when_scopes_empty(settings: Settings) -> None:
    settings.CANVAS_SCOPES = ""
    query = _query(canvas.build_authorize_url("state-abc"))
    assert "scope" not in query
    assert query["state"] == ["state-abc"]


def test_build_authorize_url_never_contains_client_secret() -> None:
    assert settings.CANVAS_CLIENT_SECRET not in canvas.build_authorize_url("s")


# --------------------------------------------------------------------------- #
# exchange_code
# --------------------------------------------------------------------------- #


@responses.activate
def test_exchange_code_posts_form_and_returns_json() -> None:
    payload = {
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {"id": 123, "name": "Jane Doe", "global_id": "1000000000123"},
    }
    responses.add(responses.POST, TOKEN_URL, json=payload, status=200)

    data = canvas.exchange_code("the-code")

    assert data == payload
    assert len(responses.calls) == 1
    call = responses.calls[0]
    assert call.request.method == "POST"
    assert call.request.url.split("?")[0] == TOKEN_URL
    body = _form_body(call)
    assert body["grant_type"] == "authorization_code"
    assert body["client_id"] == settings.CANVAS_CLIENT_ID
    assert body["client_secret"] == settings.CANVAS_CLIENT_SECRET
    assert body["redirect_uri"] == settings.CANVAS_REDIRECT_URI
    assert body["code"] == "the-code"


@responses.activate
def test_exchange_code_non_2xx_raises_without_leaking_secret() -> None:
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"error": "invalid_grant", "error_description": "bad code"},
        status=400,
    )
    with pytest.raises(CanvasOAuthError) as excinfo:
        canvas.exchange_code("bad-code")
    assert settings.CANVAS_CLIENT_SECRET not in str(excinfo.value)
    assert settings.CANVAS_CLIENT_SECRET not in repr(excinfo.value)


@responses.activate
def test_exchange_code_connection_error_raises_oauth_error() -> None:
    responses.add(responses.POST, TOKEN_URL, body=requests.ConnectionError("boom"))
    with pytest.raises(CanvasOAuthError):
        canvas.exchange_code("the-code")


# --------------------------------------------------------------------------- #
# refresh_access_token
# --------------------------------------------------------------------------- #


@responses.activate
def test_refresh_access_token_posts_refresh_grant() -> None:
    payload = {"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600}
    responses.add(responses.POST, TOKEN_URL, json=payload, status=200)

    data = canvas.refresh_access_token("refresh-1")

    assert data == payload
    body = _form_body(responses.calls[0])
    assert body["grant_type"] == "refresh_token"
    assert body["refresh_token"] == "refresh-1"
    assert body["client_id"] == settings.CANVAS_CLIENT_ID
    assert body["client_secret"] == settings.CANVAS_CLIENT_SECRET


@responses.activate
def test_refresh_access_token_400_raises() -> None:
    responses.add(responses.POST, TOKEN_URL, json={"error": "invalid_grant"}, status=400)
    with pytest.raises(CanvasOAuthError) as excinfo:
        canvas.refresh_access_token("refresh-1")
    message = str(excinfo.value)
    assert settings.CANVAS_CLIENT_SECRET not in message
    assert "refresh-1" not in message


# --------------------------------------------------------------------------- #
# revoke_token
# --------------------------------------------------------------------------- #


@responses.activate
def test_revoke_token_sends_delete_with_bearer_header() -> None:
    responses.add(responses.DELETE, TOKEN_URL, json={}, status=200)

    canvas.revoke_token("access-1")

    assert len(responses.calls) == 1
    call = responses.calls[0]
    assert call.request.method == "DELETE"
    assert call.request.url.split("?")[0] == TOKEN_URL
    assert call.request.headers["Authorization"] == "Bearer access-1"


@responses.activate
def test_revoke_token_does_not_raise_on_500() -> None:
    responses.add(responses.DELETE, TOKEN_URL, status=500)
    canvas.revoke_token("access-1")  # must not raise
    assert len(responses.calls) == 1


@responses.activate
def test_revoke_token_does_not_raise_on_connection_error() -> None:
    responses.add(responses.DELETE, TOKEN_URL, body=requests.ConnectionError("boom"))
    canvas.revoke_token("access-1")  # must not raise


# --------------------------------------------------------------------------- #
# token_expiry
# --------------------------------------------------------------------------- #


def test_token_expiry_is_timezone_aware_and_in_future() -> None:
    before = timezone.now()
    expiry = canvas.token_expiry(3600)
    after = timezone.now()
    assert timezone.is_aware(expiry)
    assert before + timedelta(seconds=3600) <= expiry <= after + timedelta(seconds=3600)


# --------------------------------------------------------------------------- #
# CanvasClient.ensure_fresh_token
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
@responses.activate
def test_ensure_fresh_token_makes_no_call_when_fresh(canvas_token: CanvasToken) -> None:
    client = CanvasClient(canvas_token)
    client.ensure_fresh_token()
    assert len(responses.calls) == 0
    assert canvas_token.access_token == "access-1"


@pytest.mark.django_db
@responses.activate
def test_ensure_fresh_token_refreshes_expired_token(expired_token: CanvasToken) -> None:
    # Canvas does not return refresh_token on a refresh grant.
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600},
        status=200,
    )
    old_expiry = expired_token.expires_at

    client = CanvasClient(expired_token)
    client.ensure_fresh_token()

    assert len(responses.calls) == 1
    body = _form_body(responses.calls[0])
    assert body["grant_type"] == "refresh_token"
    assert body["refresh_token"] == "refresh-1"

    assert expired_token.access_token == "access-2"
    assert expired_token.refresh_token == "refresh-1"
    assert expired_token.expires_at > old_expiry
    assert expired_token.expires_at > timezone.now() + timedelta(minutes=50)
    assert expired_token.is_expired() is False

    reloaded = CanvasToken.objects.get(pk=expired_token.pk)
    assert reloaded.access_token == "access-2"
    assert reloaded.refresh_token == "refresh-1"
    assert reloaded.expires_at == expired_token.expires_at


@pytest.mark.django_db
@responses.activate
def test_ensure_fresh_token_stores_new_refresh_token_when_provided(
    expired_token: CanvasToken,
) -> None:
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600},
        status=200,
    )
    CanvasClient(expired_token).ensure_fresh_token()
    reloaded = CanvasToken.objects.get(pk=expired_token.pk)
    assert reloaded.access_token == "access-2"
    assert reloaded.refresh_token == "refresh-2"


@pytest.mark.django_db
@responses.activate
def test_ensure_fresh_token_propagates_oauth_error(expired_token: CanvasToken) -> None:
    responses.add(responses.POST, TOKEN_URL, json={"error": "invalid_grant"}, status=400)
    with pytest.raises(CanvasOAuthError):
        CanvasClient(expired_token).ensure_fresh_token()
    # The stored token must be left untouched.
    reloaded = CanvasToken.objects.get(pk=expired_token.pk)
    assert reloaded.access_token == "access-1"


# --------------------------------------------------------------------------- #
# CanvasClient.get
# --------------------------------------------------------------------------- #


@pytest.mark.django_db
@responses.activate
def test_get_sends_bearer_header_and_joins_path(canvas_token: CanvasToken) -> None:
    responses.add(responses.GET, COURSES_URL, json=[{"id": 1}], status=200)

    response = CanvasClient(canvas_token).get("/api/v1/courses", params={"per_page": 50})

    assert response.status_code == 200
    assert response.json() == [{"id": 1}]
    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer access-1"
    assert request.url.split("?")[0] == COURSES_URL
    assert _query(request.url)["per_page"] == ["50"]


@pytest.mark.django_db
@responses.activate
def test_get_accepts_absolute_url(canvas_token: CanvasToken) -> None:
    absolute = f"{COURSES_URL}?page=2"
    responses.add(responses.GET, absolute, json=[], status=200)
    response = CanvasClient(canvas_token).get(absolute)
    assert response.status_code == 200
    assert responses.calls[0].request.url.split("?")[0] == COURSES_URL


@pytest.mark.django_db
@responses.activate(registry=OrderedRegistry)
def test_get_refreshes_once_and_retries_on_401(canvas_token: CanvasToken) -> None:
    responses.add(responses.GET, COURSES_URL, json={"errors": "unauthorized"}, status=401)
    responses.add(
        responses.POST,
        TOKEN_URL,
        json={"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600},
        status=200,
    )
    responses.add(responses.GET, COURSES_URL, json=[{"id": 1}], status=200)

    response = CanvasClient(canvas_token).get("/api/v1/courses")

    assert response.status_code == 200
    assert len(responses.calls) == 3

    first, refresh, retry = responses.calls
    assert first.request.method == "GET"
    assert first.request.headers["Authorization"] == "Bearer access-1"
    assert first.response.status_code == 401

    assert refresh.request.method == "POST"
    assert refresh.request.url.split("?")[0] == TOKEN_URL
    assert _form_body(refresh)["grant_type"] == "refresh_token"

    assert retry.request.method == "GET"
    assert retry.request.headers["Authorization"] == "Bearer access-2"

    assert CanvasToken.objects.get(pk=canvas_token.pk).access_token == "access-2"


@pytest.mark.django_db
@responses.activate(registry=OrderedRegistry)
def test_get_raises_after_second_401(canvas_token: CanvasToken) -> None:
    responses.add(responses.GET, COURSES_URL, status=401)
    responses.add(responses.POST, TOKEN_URL, json={"access_token": "access-2", "expires_in": 3600})
    responses.add(responses.GET, COURSES_URL, status=401)

    with pytest.raises((CanvasAPIError, CanvasOAuthError)):
        CanvasClient(canvas_token).get("/api/v1/courses")
    # Exactly one refresh; no infinite retry loop.
    assert len(responses.calls) == 3


@pytest.mark.django_db
@responses.activate
def test_get_raises_api_error_with_status_code_on_403(canvas_token: CanvasToken) -> None:
    responses.add(responses.GET, COURSES_URL, json={"errors": "forbidden"}, status=403)

    with pytest.raises(CanvasAPIError) as excinfo:
        CanvasClient(canvas_token).get("/api/v1/courses")

    assert excinfo.value.status_code == 403
    assert len(responses.calls) == 1
    assert "access-1" not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# CanvasClient.get_paginated / list_courses
# --------------------------------------------------------------------------- #


def _page_two_url() -> str:
    return f"{COURSES_URL}?page=2&per_page=50"


@pytest.mark.django_db
@responses.activate(registry=OrderedRegistry)
def test_get_paginated_follows_link_header(canvas_token: CanvasToken) -> None:
    page_two = _page_two_url()
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[{"id": 1}, {"id": 2}],
        status=200,
        headers={"Link": f'<{page_two}>; rel="next", <{COURSES_URL}?page=1>; rel="current"'},
    )
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[{"id": 3}],
        status=200,
        headers={"Link": f'<{COURSES_URL}?page=1>; rel="first"'},
    )

    items = CanvasClient(canvas_token).get_paginated("/api/v1/courses", {"per_page": 50})

    assert items == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert len(responses.calls) == 2
    second = responses.calls[1].request
    assert second.url.split("?")[0] == COURSES_URL
    assert _query(second.url)["page"] == ["2"]
    assert second.headers["Authorization"] == "Bearer access-1"


@pytest.mark.django_db
@responses.activate(registry=OrderedRegistry)
def test_list_courses_combines_pages_and_sends_params(canvas_token: CanvasToken) -> None:
    page_two = _page_two_url()
    course_one = {
        "id": 1,
        "name": "Intro to Testing",
        "course_code": "TEST-101",
        "enrollments": [{"type": "student"}],
        "term": {"name": "Fall 2026"},
    }
    course_two = {
        "id": 2,
        "name": "Advanced Testing",
        "course_code": "TEST-201",
        "enrollments": [{"type": "teacher"}],
    }
    responses.add(
        responses.GET,
        COURSES_URL,
        json=[course_one],
        status=200,
        headers={"Link": f'<{page_two}>; rel="next"'},
    )
    responses.add(responses.GET, COURSES_URL, json=[course_two], status=200)

    courses = CanvasClient(canvas_token).list_courses()

    assert courses == [course_one, course_two]
    assert len(responses.calls) == 2
    first_query = _query(responses.calls[0].request.url)
    assert first_query["enrollment_state"] == ["active"]
    assert first_query["per_page"] == ["50"]
    assert first_query["include[]"] == ["term"]


@pytest.mark.django_db
@responses.activate
def test_list_courses_single_page_without_link_header(canvas_token: CanvasToken) -> None:
    responses.add(responses.GET, COURSES_URL, json=[{"id": 9, "name": "Solo"}], status=200)
    assert CanvasClient(canvas_token).list_courses() == [{"id": 9, "name": "Solo"}]
    assert len(responses.calls) == 1
