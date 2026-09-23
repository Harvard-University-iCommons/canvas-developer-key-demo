"""URL configuration for the Canvas Developer Key OAuth demo."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("canvas_oauth.urls")),
    path("admin/", admin.site.urls),
]
