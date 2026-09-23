from django.contrib import admin

from canvas_oauth.models import CanvasToken


@admin.register(CanvasToken)
class CanvasTokenAdmin(admin.ModelAdmin):
    """Admin for CanvasToken. Encrypted token fields are never displayed."""

    list_display = ("canvas_user_id", "canvas_user_name", "expires_at", "updated_at")
    fields = ("user", "canvas_user_id", "canvas_user_name", "expires_at", "updated_at")
    readonly_fields = ("updated_at",)
    exclude = ("encrypted_access_token", "encrypted_refresh_token")
    search_fields = ("canvas_user_id", "canvas_user_name")
    ordering = ("-updated_at",)

    def has_add_permission(self, request) -> bool:  # type: ignore[override]
        # Tokens are only created through the OAuth flow.
        return False
