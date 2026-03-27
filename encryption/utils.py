import hashlib
import os
from dataclasses import dataclass

from Crypto.Cipher import AES
from django.conf import settings


@dataclass
class FermatTrace:
    base: int
    modulus: int
    exponent: int
    result: int


@dataclass
class KeyMaterial:
    key: bytes
    salt_hex: str
    trace: FermatTrace


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fermat_trace(seed_text: str) -> FermatTrace:
    modulus = 65537
    base = sum(ord(ch) for ch in seed_text) % modulus
    if base in (0, 1):
        base = 3
    exponent = modulus - 1
    result = pow(base, exponent, modulus)
    return FermatTrace(base=base, modulus=modulus, exponent=exponent, result=result)


def derive_key(owner_id: int, file_hash: str, salt_hex: str | None = None) -> KeyMaterial:
    if salt_hex is None:
        salt_hex = os.urandom(16).hex()
    seed_text = f"{owner_id}:{file_hash}:{salt_hex}:{settings.SECURECLOUD_MASTER_SECRET}"
    trace = fermat_trace(seed_text)
    key_source = f"{seed_text}:{trace.result}:{trace.base}:{trace.modulus}".encode("utf-8")
    key = hashlib.sha256(key_source).digest()
    return KeyMaterial(key=key, salt_hex=salt_hex, trace=trace)


def encrypt_bytes(plain: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return ciphertext, cipher.nonce.hex(), tag.hex()


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce_hex: str, tag_hex: str) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
    return cipher.decrypt_and_verify(ciphertext, bytes.fromhex(tag_hex))
