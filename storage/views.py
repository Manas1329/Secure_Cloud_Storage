from io import BytesIO

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.models import User
from encryption.utils import decrypt_bytes, derive_key, encrypt_bytes, sha256_hex
from storage.forms import ShareFileForm, UploadFileForm
from storage.models import AuditLog, SecureFile
from storage.services import list_visible_files, log_event, search_files_for_user, user_can_access_file


@login_required
def file_list(request):
	query = request.GET.get("q", "")
	files = search_files_for_user(request.user, query)
	return render(request, "storage/file_list.html", {"files": files, "query": query})


@login_required
def upload_file(request):
	if request.user.role == User.Role.VIEWER:
		messages.error(request, "Viewer accounts cannot upload files.")
		return redirect("accounts:dashboard")

	if request.method == "POST":
		form = UploadFileForm(request.POST, request.FILES)
		if form.is_valid():
			source = form.cleaned_data["source_file"]
			plain_bytes = source.read()
			file_size = len(plain_bytes)

			if request.user.role == User.Role.USER and request.user.storage_used + file_size > request.user.storage_limit:
				messages.error(request, "Storage limit exceeded.")
				return redirect("storage:upload")

			file_hash = sha256_hex(plain_bytes)
			key_material = derive_key(request.user.id, file_hash)
			encrypted_bytes, nonce_hex, tag_hex = encrypt_bytes(plain_bytes, key_material.key)

			secure_file = form.save(commit=False)
			secure_file.owner = request.user
			secure_file.original_name = source.name
			secure_file.file_size = file_size
			secure_file.sha256_hash = file_hash
			secure_file.encryption_key_digest = sha256_hex(key_material.key)
			secure_file.key_salt = key_material.salt_hex
			secure_file.fermat_base = key_material.trace.base
			secure_file.fermat_modulus = key_material.trace.modulus
			secure_file.fermat_result = key_material.trace.result
			secure_file.aes_nonce = nonce_hex
			secure_file.aes_tag = tag_hex
			secure_file.encrypted_file.save(f"{source.name}.enc", ContentFile(encrypted_bytes), save=False)
			secure_file.save()
			secure_file.shared_with.set(form.cleaned_data["share_with"])

			request.user.storage_used += file_size
			request.user.save(update_fields=["storage_used"])

			log_event(request, request.user, AuditLog.Action.UPLOAD, secure_file, "Encrypted upload completed")
			messages.success(request, "File uploaded and encrypted successfully.")
			return redirect("storage:files")
	else:
		form = UploadFileForm()

	return render(request, "storage/upload.html", {"form": form})


@login_required
def delete_file(request, file_id):
	secure_file = get_object_or_404(SecureFile, id=file_id)
	if request.user.role != User.Role.ADMIN and secure_file.owner_id != request.user.id:
		return HttpResponseForbidden("You do not have permission to delete this file.")

	size_to_deduct = secure_file.file_size
	owner = secure_file.owner
	secure_file.delete()

	if owner.role == User.Role.USER:
		owner.storage_used = max(0, owner.storage_used - size_to_deduct)
		owner.save(update_fields=["storage_used"])

	log_event(request, request.user, AuditLog.Action.DELETE, details="File deleted")
	messages.success(request, "File deleted.")
	return redirect("storage:files")


def _validate_download_gate(request, secure_file):
	if secure_file.is_expired:
		messages.error(request, "This file has expired.")
		return False
	if not secure_file.can_download_more:
		messages.error(request, "Download limit reached for this file.")
		return False
	if not user_can_access_file(request.user, secure_file):
		return False
	return True


def _decrypt_for_response(secure_file):
	encrypted_bytes = secure_file.encrypted_file.read()
	key_material = derive_key(secure_file.owner_id, secure_file.sha256_hash, secure_file.key_salt)
	decrypted = decrypt_bytes(encrypted_bytes, key_material.key, secure_file.aes_nonce, secure_file.aes_tag)
	recomputed_hash = sha256_hex(decrypted)
	if recomputed_hash != secure_file.sha256_hash:
		raise ValueError("Integrity check failed")
	return decrypted, key_material


@login_required
def download_file(request, file_id):
	secure_file = get_object_or_404(SecureFile, id=file_id)
	if not _validate_download_gate(request, secure_file):
		return redirect("storage:files")

	try:
		decrypted, _ = _decrypt_for_response(secure_file)
	except Exception:
		messages.error(request, "Decryption failed or integrity check mismatch.")
		return redirect("storage:files")

	secure_file.download_count += 1
	secure_file.save(update_fields=["download_count"])
	log_event(request, request.user, AuditLog.Action.DOWNLOAD, secure_file, "File downloaded with integrity check")
	return FileResponse(BytesIO(decrypted), as_attachment=True, filename=secure_file.original_name)


@login_required
def view_file(request, file_id):
	secure_file = get_object_or_404(SecureFile, id=file_id)
	if not _validate_download_gate(request, secure_file):
		return redirect("storage:files")

	try:
		decrypted, _ = _decrypt_for_response(secure_file)
	except Exception:
		messages.error(request, "Decryption failed or integrity check mismatch.")
		return redirect("storage:files")

	secure_file.download_count += 1
	secure_file.save(update_fields=["download_count"])
	log_event(request, request.user, AuditLog.Action.VIEW, secure_file, "File viewed inline")

	response = FileResponse(BytesIO(decrypted), as_attachment=False, filename=secure_file.original_name)
	if secure_file.original_name.lower().endswith(".pdf"):
		response["Content-Type"] = "application/pdf"
	return response


@login_required
def share_file(request, file_id):
	secure_file = get_object_or_404(SecureFile, id=file_id)
	if request.user.role not in (User.Role.ADMIN, User.Role.USER):
		return HttpResponseForbidden("Insufficient permissions")
	if request.user.role != User.Role.ADMIN and secure_file.owner_id != request.user.id:
		return HttpResponseForbidden("You can only share your own files")

	if request.method == "POST":
		form = ShareFileForm(request.POST)
		if form.is_valid():
			viewers = form.cleaned_data["viewers"]
			secure_file.shared_with.set(viewers)
			viewer_list = ", ".join(v.username for v in viewers) or "none"
			log_event(request, request.user, AuditLog.Action.SHARE, secure_file, f"Shared with: {viewer_list}")
			messages.success(request, "Sharing permissions updated.")
			return redirect("storage:files")
	else:
		form = ShareFileForm(initial={"viewers": secure_file.shared_with.all()})

	return render(request, "storage/share_file.html", {"file": secure_file, "form": form})


@login_required
def shared_files(request):
	files = list_visible_files(request.user)
	return render(request, "storage/shared_files.html", {"files": files})


@login_required
def download_history_data(request):
	files = list_visible_files(request.user)
	labels = [item.original_name for item in files[:8]]
	values = [item.download_count for item in files[:8]]
	return render(request, "storage/history_chart_fragment.html", {"labels": labels, "values": values})
