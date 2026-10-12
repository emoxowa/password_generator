"""Функции для хеширования, шифрования и генерации паролей."""

import hashlib
import hmac
import os
import secrets
import string
from pathlib import Path

from cryptography.fernet import Fernet

KEY_PATH = Path(__file__).parent / ".key"


# --- Мастер-пароль (SHA-256) ---

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Возвращает (sha256-хеш, соль). Соль защищает от радужных таблиц."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    digest, _ = hash_password(password, salt)
    return hmac.compare_digest(digest, stored_hash)


# --- Шифрование записей (Fernet) ---

def load_or_create_key(key_path: Path = KEY_PATH) -> bytes:
    """Читает ключ из файла .key; если файла нет — генерирует новый."""
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    os.chmod(key_path, 0o600)  # доступ к ключу только у владельца
    return key


def encrypt(fernet: Fernet, plaintext: str) -> bytes:
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt(fernet: Fernet, token: bytes) -> str:
    return fernet.decrypt(token).decode("utf-8")


# --- Генерация паролей ---

def generate_password(length: int = 16) -> str:
    """Генерирует надёжный пароль: минимум по одному символу каждого типа."""
    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+?"]
    alphabet = "".join(groups)
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(alphabet) for _ in range(length - len(groups))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
