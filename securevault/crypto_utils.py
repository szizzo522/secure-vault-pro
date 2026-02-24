import base64
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from securevault.config import SALT, KDF_ITERATIONS, BACKEND


def derive_key(master_password: str) -> bytes:
    """
    Derive a Fernet key from the provided master password using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=KDF_ITERATIONS,
        backend=BACKEND,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_text(text: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(text.encode("utf-8"))


def decrypt_text(token: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(token).decode("utf-8")
