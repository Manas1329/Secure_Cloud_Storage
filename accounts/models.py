from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
	class Role(models.TextChoices):
		ADMIN = "ADMIN", "Admin"
		USER = "USER", "User"
		VIEWER = "VIEWER", "Viewer"

	role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER)
	storage_used = models.BigIntegerField(default=0)
	storage_limit = models.BigIntegerField(default=1024 * 1024 * 1024)

	def save(self, *args, **kwargs):
		if self.role == self.Role.ADMIN:
			self.storage_limit = 0
		elif self.role == self.Role.VIEWER:
			self.storage_limit = 0
		elif not self.storage_limit:
			self.storage_limit = 1024 * 1024 * 1024
		super().save(*args, **kwargs)

	@property
	def storage_usage_percent(self):
		if self.storage_limit <= 0:
			return 0
		return min(100, int((self.storage_used / self.storage_limit) * 100))
