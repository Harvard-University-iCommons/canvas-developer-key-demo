"""Views implementing the Canvas OAuth2 authorization code flow."""

import logging
import secrets

from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.crypto import constant_time_compare
from django.views.decorators.http import require_GET, require_POST

from canvas_oauth import canvas
from canvas_oauth.models import CanvasToken

logger = logging.getLogger(__name__)


def _error(request: HttpRequest, message: str, status: int) -> HttpResponse:
    return render(request, "canvas_oauth/error.html", {"message": message}, status=status)


@require_GET
def home(request: HttpRequest) -> HttpResponse:
    return render(request, "canvas_oauth/home.html")


@require_GET
def login(request: HttpRequest) -> HttpResponse:
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    return redirect(canvas.build_authorize_url(state))


@require_GET
def callback(request: HttpRequest) -> HttpResponse:
    if "error" in request.GET:
        logger.info("Canvas authorization was denied or failed: %s", request.GET.get("error"))
        return _error(
            request,
            "Canvas did not authorize this application. You can try signing in again.",
            status=403,
        )

    expected = request.session.pop("oauth_state", None)
    got = request.GET.get("state")
    if not expected or not got or not constant_time_compare(expected, got):
        logger.warning("OAuth callback state mismatch or missing state")
        return _error(
            request,
            "The sign-in request could not be verified. Please start again.",
            status=400,
        )

    code = request.GET.get("code")
    if not code:
        return _error(request, "Canvas did not return an authorization code.", status=400)

    try:
        data = canvas.exchange_code(code)
    except canvas.CanvasOAuthError as exc:
        return _error(request, str(exc), status=502)

    try:
        canvas_user_id = int(data["user"]["id"])
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        expires_at = canvas.token_expiry(data["expires_in"])
    except (KeyError, TypeError, ValueError):
        logger.warning("Canvas token response was missing required fields")
        return _error(request, "Canvas returned an incomplete token response.", status=502)
    name = data["user"].get("name") or ""

    user_model = auth.get_user_model()
    user, created = user_model.objects.get_or_create(
        username=f"canvas-{canvas_user_id}",
        defaults={"first_name": name[:150]},
    )
    if created:
        user.set_unusable_password()
        user.save()

    token, _ = CanvasToken.objects.update_or_create(
        canvas_user_id=canvas_user_id,
        defaults={
            "user": user,
            "canvas_user_name": name[:255],
            "expires_at": expires_at,
        },
    )
    token.access_token = access_token
    token.refresh_token = refresh_token
    token.save()

    auth.login(request, user)
    logger.info("Canvas user %s signed in", canvas_user_id)
    return redirect("canvas_oauth:courses")


@require_GET
@login_required
def courses(request: HttpRequest) -> HttpResponse:
    try:
        token = request.user.canvas_token
    except CanvasToken.DoesNotExist:
        return redirect("canvas_oauth:login")

    try:
        course_list = canvas.CanvasClient(token).list_courses()
    except canvas.CanvasOAuthError:
        # The refresh token no longer works (revoked or expired). Drop the
        # stale token and ask the user to authorize again.
        logger.info(
            "Token refresh failed for canvas_user_id=%s; re-authorizing", token.canvas_user_id
        )
        token.delete()
        return redirect("canvas_oauth:login")
    except canvas.CanvasAPIError as exc:
        return _error(request, str(exc), status=502)

    return render(request, "canvas_oauth/courses.html", {"courses": course_list})


@login_required
@require_POST
def logout(request: HttpRequest) -> HttpResponse:
    try:
        token = request.user.canvas_token
    except CanvasToken.DoesNotExist:
        token = None

    if token is not None:
        canvas.revoke_token(token.access_token)
        token.delete()

    auth.logout(request)
    return redirect("canvas_oauth:home")
