from django.urls import path

from accounts.views import (
    SecureLoginView,
    dashboard,
    logout_view,
    profile,
    register,
)

app_name = "accounts"

urlpatterns = [
    path("login/", SecureLoginView.as_view(), name="login"),
    path("register/", register, name="register"),
    path("dashboard/", dashboard, name="dashboard"),
    path("profile/", profile, name="profile"),
    path("logout/", logout_view, name="logout"),
]
