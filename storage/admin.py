from django.contrib import admin
from storage.models import AuditLog, SecureFile


@admin.register(SecureFile)
class SecureFileAdmin(admin.ModelAdmin):
	list_display = (
		"id",
		"original_name",
		"owner",
		"file_size",
		"download_count",
		"download_limit",
		"expiry_date",
		"upload_date",
	)
	search_fields = ("original_name", "owner__username", "sha256_hash")
	list_filter = ("upload_date", "expiry_date")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
	list_display = ("timestamp", "user", "action", "ip_address", "file_reference")
	search_fields = ("user__username", "action", "details")
	list_filter = ("action", "timestamp")
