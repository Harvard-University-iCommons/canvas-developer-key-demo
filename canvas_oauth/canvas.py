"""Canvas LMS OAuth2 and REST API helpers.

Nothing in this module logs or embeds token values, client secrets, or
authorization codes in exception messages.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.utils import timezone

if TYPE_CHECKING:
    from canvas_oauth.models import CanvasToken

logger = logging.getLogger(__name__)


class CanvasOAuthError(Exception):
    """Raised when an OAuth token request to Canvas fails."""


class CanvasAPIError(Exception):
    """Raised when a Canvas REST API call returns a non-2xx response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _token_endpoint() -> str:
    return f"{settings.CANVAS_BASE_URL}/login/oauth2/token"


def build_authorize_url(state: str) -> str:
    """Return the Canvas authorization URL for the given CSRF ``state``."""
    params = {
        "client_id": settings.CANVAS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.CANVAS_REDIRECT_URI,
        "state": state,
    }
    if settings.CANVAS_SCOPES:
        params["scope"] = settings.CANVAS_SCOPES
    return f"{settings.CANVAS_BASE_URL}/login/oauth2/auth?{urlencode(params)}"


def _post_token(data: dict[str, str], action: str) -> dict:
    try:
        response = requests.post(
            _token_endpoint(),
            data=data,
            timeout=settings.CANVAS_HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("Canvas token %s failed: network error (%s)", action, type(exc).__name__)
        raise CanvasOAuthError(f"Could not reach Canvas to {action}.") from exc

    if not response.ok:
        logger.warning("Canvas token %s failed: HTTP %s", action, response.status_code)
        raise CanvasOAuthError(
            f"Canvas rejected the {action} request (HTTP {response.status_code})."
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise CanvasOAuthError(f"Canvas returned an invalid response to {action}.") from exc

    if not isinstance(payload, dict) or "access_token" not in payload:
        raise CanvasOAuthError(f"Canvas response to {action} did not include an access token.")
    return payload


def exchange_code(code: str) -> dict:
    """Exchange an authorization code for tokens (authorization_code grant)."""
    return _post_token(
        {
            "grant_type": "authorization_code",
            "client_id": settings.CANVAS_CLIENT_ID,
            "client_secret": settings.CANVAS_CLIENT_SECRET,
            "redirect_uri": settings.CANVAS_REDIRECT_URI,
            "code": code,
        },
        action="exchange the authorization code",
    )


def refresh_access_token(refresh_token: str) -> dict:
    """Obtain a new access token using a refresh token (refresh_token grant)."""
    return _post_token(
        {
            "grant_type": "refresh_token",
            "client_id": settings.CANVAS_CLIENT_ID,
            "client_secret": settings.CANVAS_CLIENT_SECRET,
            "refresh_token": refresh_token,
        },
        action="refresh the access token",
    )


def revoke_token(access_token: str) -> None:
    """Best-effort revocation of an access token. Never raises."""
    try:
        response = requests.delete(
            _token_endpoint(),
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=settings.CANVAS_HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("Canvas token revocation failed: network error (%s)", type(exc).__name__)
        return
    if not response.ok:
        logger.warning("Canvas token revocation returned HTTP %s", response.status_code)
    else:
        logger.info("Canvas token revoked")


def token_expiry(expires_in: int) -> datetime:
    """Return the absolute expiry time for a token valid for ``expires_in`` seconds."""
    return timezone.now() + timedelta(seconds=int(expires_in))


class CanvasClient:
    """Authenticated Canvas API client that transparently refreshes its token."""

    def __init__(self, token: CanvasToken) -> None:
        self.token = token

    def _refresh(self) -> None:
        data = refresh_access_token(self.token.refresh_token)
        self.token.access_token = data["access_token"]
        self.token.expires_at = token_expiry(data.get("expires_in", 3600))
        if data.get("refresh_token"):
            self.token.refresh_token = data["refresh_token"]
        self.token.save()
        logger.info(
            "Refreshed Canvas access token for canvas_user_id=%s", self.token.canvas_user_id
        )

    def ensure_fresh_token(self) -> None:
        """Refresh the access token if it has expired (or is about to)."""
        if self.token.is_expired():
            self._refresh()

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return f"{settings.CANVAS_BASE_URL}/{path_or_url.lstrip('/')}"

    def _request(self, url: str, params: dict | None) -> requests.Response:
        try:
            return requests.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.token.access_token}"},
                timeout=settings.CANVAS_HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("Canvas API request failed: network error (%s)", type(exc).__name__)
            raise CanvasAPIError("Could not reach the Canvas API.") from exc

    def get(self, path_or_url: str, params: dict | None = None) -> requests.Response:
        """GET a Canvas API path or absolute URL, refreshing the token as needed."""
        self.ensure_fresh_token()
        url = self._url(path_or_url)
        response = self._request(url, params)
        if response.status_code == 401:
            logger.info("Canvas API returned 401; refreshing token and retrying once")
            self._refresh()
            response = self._request(url, params)
        if not response.ok:
            logger.warning("Canvas API returned HTTP %s for %s", response.status_code, url)
            raise CanvasAPIError(
                f"Canvas API request failed (HTTP {response.status_code}).",
                status_code=response.status_code,
            )
        return response

    def get_paginated(self, path: str, params: dict | None = None) -> list[dict]:
        """GET all pages of a list endpoint by following Link rel="next"."""
        results: list[dict] = []
        response = self.get(path, params)
        while True:
            page = response.json()
            if isinstance(page, list):
                results.extend(page)
            next_link = response.links.get("next", {}).get("url")
            if not next_link:
                break
            # The next URL already carries the query parameters.
            response = self.get(next_link)
        return results

    def list_courses(self) -> list[dict]:
        """List the user's active course enrollments, including term info."""
        return self.get_paginated(
            "/api/v1/courses",
            {"enrollment_state": "active", "per_page": 50, "include[]": "term"},
        )
