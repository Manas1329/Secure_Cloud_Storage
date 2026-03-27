from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy

from accounts.forms import LoginForm, ProfileForm, RegisterForm
from accounts.models import User
from storage.models import AuditLog, SecureFile
from storage.services import log_event


def home(request):
	return render(request, "home.html")


class SecureLoginView(LoginView):
	template_name = "accounts/login.html"
	authentication_form = LoginForm

	def get_success_url(self):
		return reverse_lazy("accounts:dashboard")

	def form_valid(self, form):
		response = super().form_valid(form)
		log_event(self.request, self.request.user, AuditLog.Action.LOGIN, details="User login successful")
		return response


def register(request):
	if request.method == "POST":
		form = RegisterForm(request.POST)
		if form.is_valid():
			user = form.save(commit=False)
			user.role = form.cleaned_data["role"]
			if user.role == User.Role.USER:
				user.storage_limit = 1024 * 1024 * 1024
			else:
				user.storage_limit = 0
			user.save()
			login(request, user)
			log_event(request, user, AuditLog.Action.LOGIN, details="User registered and logged in")
			messages.success(request, "Welcome to SecureCloud.")
			return redirect("accounts:dashboard")
	else:
		form = RegisterForm()
	return render(request, "accounts/register.html", {"form": form})


@login_required
def dashboard(request):
	user = request.user
	if user.role == User.Role.ADMIN:
		context = {
			"users_count": User.objects.count(),
			"files_count": SecureFile.objects.count(),
			"recent_logs": AuditLog.objects.select_related("user")[:10],
		}
		return render(request, "accounts/admin_dashboard.html", context)

	if user.role == User.Role.USER:
		context = {
			"file_count": SecureFile.objects.filter(owner=user).count(),
			"recent_uploads": SecureFile.objects.filter(owner=user)[:5],
			"storage_percent": user.storage_usage_percent,
		}
		return render(request, "accounts/user_dashboard.html", context)

	context = {
		"shared_count": SecureFile.objects.filter(shared_with=user).count(),
		"recent_shared": SecureFile.objects.filter(shared_with=user)[:5],
	}
	return render(request, "accounts/viewer_dashboard.html", context)


@login_required
def profile(request):
	user = request.user
	if request.method == "POST":
		profile_form = ProfileForm(request.POST, instance=user)
		password_form = PasswordChangeForm(user, request.POST)
		if "update_profile" in request.POST and profile_form.is_valid():
			profile_form.save()
			log_event(request, user, AuditLog.Action.PROFILE_UPDATE, details="Profile updated")
			messages.success(request, "Profile updated.")
			return redirect("accounts:profile")
		if "change_password" in request.POST and password_form.is_valid():
			password_form.save()
			log_event(request, user, AuditLog.Action.PROFILE_UPDATE, details="Password changed")
			messages.success(request, "Password changed successfully.")
			return redirect("accounts:login")
	else:
		profile_form = ProfileForm(instance=user)
		password_form = PasswordChangeForm(user)

	logs = AuditLog.objects.filter(user=user)[:12]
	return render(
		request,
		"accounts/profile.html",
		{
			"profile_form": profile_form,
			"password_form": password_form,
			"logs": logs,
		},
	)


@login_required
def logout_view(request):
	logout(request)
	messages.info(request, "You have been logged out.")
	return redirect("home")
