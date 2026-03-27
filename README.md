# SecureCloud

SecureCloud is a Django-based secure file storage system with role-based access control and a multi-layer encryption/decryption demonstration pipeline.

## Implemented Security Layers

- SHA-256 file integrity digest generation and verification.
- Fermat-based validation trace integrated into key derivation.
- AES-GCM authenticated encryption/decryption for file confidentiality and integrity.

## Roles

- Admin: full access to all files, logs, users, and admin dashboard capabilities.
- User: upload/download/view/delete own files, share with viewers, set expiry and download limits, storage capped to 1 GB.
- Viewer: can only access shared files and profile/audit view, no uploads.

## Setup

1. Create and activate a Python virtual environment.
2. Install dependencies:
   - django
   - pycryptodome
3. Copy .env.example values into your environment variables.
4. Run migrations:
   - python manage.py makemigrations
   - python manage.py migrate
5. Create an admin user:
   - python manage.py createsuperuser
6. Start server:
   - python manage.py runserver

## Project Apps

- accounts: custom user model, auth, dashboards, profile.
- storage: secure file metadata, audit logs, upload/download/share flows.
- encryption: cryptographic utility module for hash/key/encryption/decryption.

## Notes

- Files are persisted in encrypted form only under media/encrypted.
- Password handling uses Django authentication hashing (not plaintext).
- The encryption visualization popup is available on file actions pages.
