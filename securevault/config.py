from cryptography.hazmat.backends import default_backend

APP_TITLE = "SecureVault — Samuel Zizzo"
WINDOW_SIZE = "520x420"

DB_PATH = "securevault.db"

# NOTE: Keeping your salt approach to stay close to original code.
# For a more secure version, store a random per-user salt in DB.
SALT = b"2444"

KDF_ITERATIONS = 100_000
BACKEND = default_backend()
