from django.urls import path

from canvas_oauth import views

app_name = "canvas_oauth"

urlpatterns = [
    path("", views.home, name="home"),
    path("oauth/login/", views.login, name="login"),
    path("oauth/callback/", views.callback, name="callback"),
    path("courses/", views.courses, name="courses"),
    path("logout/", views.logout, name="logout"),
]
