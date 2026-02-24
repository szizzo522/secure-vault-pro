import hashlib
import random
import string
import uuid


def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_recovery_key() -> str:
    return uuid.uuid4().hex


def generate_random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))
