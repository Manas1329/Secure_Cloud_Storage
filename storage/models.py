from django.conf import settings
from django.db import models
from django.utils import timezone


class SecureFile(models.Model):
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name="owned_files",
	)
	encrypted_file = models.FileField(upload_to="encrypted/")
	original_name = models.CharField(max_length=255)
	sha256_hash = models.CharField(max_length=64)
	encryption_key_digest = models.CharField(max_length=64)
	key_salt = models.CharField(max_length=64)
	fermat_base = models.PositiveBigIntegerField(default=0)
	fermat_modulus = models.PositiveBigIntegerField(default=0)
	fermat_result = models.PositiveBigIntegerField(default=0)
	aes_nonce = models.CharField(max_length=64)
	aes_tag = models.CharField(max_length=64)
	file_size = models.BigIntegerField(default=0)
	upload_date = models.DateTimeField(auto_now_add=True)
	expiry_date = models.DateTimeField(null=True, blank=True)
	download_limit = models.PositiveIntegerField(default=1)
	download_count = models.PositiveIntegerField(default=0)
	description = models.TextField(blank=True)
	shared_with = models.ManyToManyField(
		settings.AUTH_USER_MODEL,
		related_name="shared_files",
		blank=True,
	)

	class Meta:
		ordering = ["-upload_date"]

	def __str__(self):
		return f"{self.original_name} ({self.owner.username})"

	@property
	def is_expired(self):
		return bool(self.expiry_date and timezone.now() > self.expiry_date)

	@property
	def can_download_more(self):
		return self.download_limit == 0 or self.download_count < self.download_limit


class SecureFileShare(models.Model):
	class Permission(models.TextChoices):
		VIEW = "view", "View only"
		VIEW_DOWNLOAD = "view_download", "View and download"

	secure_file = models.ForeignKey(SecureFile, on_delete=models.CASCADE, related_name="share_entries")
	viewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="file_access_entries")
	permission = models.CharField(max_length=20, choices=Permission.choices, default=Permission.VIEW)
	shared_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		unique_together = ("secure_file", "viewer")
		ordering = ["-shared_at"]

	@property
	def can_download(self):
		return self.permission == self.Permission.VIEW_DOWNLOAD


class AuditLog(models.Model):
	class Action(models.TextChoices):
		UPLOAD = "upload", "Upload"
		DOWNLOAD = "download", "Download"
		DELETE = "delete", "Delete"
		LOGIN = "login", "Login"
		SHARE = "share", "Share"
		VIEW = "view", "View"
		PROFILE_UPDATE = "profile_update", "Profile Update"

	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="audit_logs")
	action = models.CharField(max_length=40, choices=Action.choices)
	timestamp = models.DateTimeField(auto_now_add=True)
	ip_address = models.GenericIPAddressField(null=True, blank=True)
	file_reference = models.ForeignKey(SecureFile, on_delete=models.SET_NULL, null=True, blank=True)
	details = models.TextField(blank=True)

	class Meta:
		ordering = ["-timestamp"]

	def __str__(self):
		return f"{self.user.username} - {self.action}"
