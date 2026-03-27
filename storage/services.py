from django.db.models import Q

from accounts.models import User
from storage.models import AuditLog, SecureFile


def get_client_ip(request):
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_event(request, user, action, file_reference=None, details=""):
    AuditLog.objects.create(
        user=user,
        action=action,
        ip_address=get_client_ip(request),
        file_reference=file_reference,
        details=details,
    )


def user_can_access_file(user: User, secure_file: SecureFile):
    if user.role == User.Role.ADMIN:
        return True
    if secure_file.owner_id == user.id:
        return True
    return secure_file.shared_with.filter(id=user.id).exists()


def list_visible_files(user: User):
    if user.role == User.Role.ADMIN:
        return SecureFile.objects.all()
    if user.role == User.Role.USER:
        return SecureFile.objects.filter(owner=user)
    return SecureFile.objects.filter(shared_with=user)


def search_files_for_user(user: User, query: str):
    files = list_visible_files(user)
    if not query:
        return files
    return files.filter(Q(original_name__icontains=query) | Q(description__icontains=query))
