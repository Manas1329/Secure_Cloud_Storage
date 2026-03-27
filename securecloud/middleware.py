from django.contrib import messages
from django.shortcuts import redirect

from accounts.models import User


class RoleAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        protected_prefixes = ("/storage/", "/accounts/dashboard", "/accounts/profile")
        if request.user.is_authenticated and request.path.startswith(protected_prefixes):
            if request.user.role == User.Role.VIEWER and request.path in (
                "/storage/upload/",
            ):
                messages.error(request, "Viewers do not have upload permissions.")
                return redirect("accounts:dashboard")
        return self.get_response(request)


class StorageLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and request.path == "/storage/upload/" and request.method == "POST":
            if request.user.role == User.Role.VIEWER:
                messages.error(request, "Viewer accounts cannot upload files.")
                return redirect("accounts:dashboard")
        return self.get_response(request)
