from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from accounts.models import User


@admin.register(User)
class SecureCloudUserAdmin(UserAdmin):
	fieldsets = UserAdmin.fieldsets + (
		(
			"SecureCloud",
			{
				"fields": (
					"role",
					"storage_used",
					"storage_limit",
				)
			},
		),
	)
	list_display = ("username", "email", "role", "storage_used", "storage_limit", "is_staff")
	list_filter = ("role", "is_staff", "is_superuser")
