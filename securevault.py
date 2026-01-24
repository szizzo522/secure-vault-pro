"""
SecureVault — Password Vault (SQLite + Fernet Encryption)
Created by Samuel Zizzo — 2025
MIT License
"""

import base64
import hashlib
import random
import sqlite3
import string
import uuid
import tkinter as tk
from tkinter import simpledialog, ttk, messagebox

import pyperclip
import qrcode
from PIL import ImageTk

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# ----------------------------
# Encryption Setup
# ----------------------------

# NOTE: Keeping your salt approach to stay close to your original code.
# For a production app, you'd want a per-user random salt stored in DB.
backend = default_backend()
SALT = b"2444"

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=100_000,
    backend=backend,
)

encryption_key: bytes | None = None


def derive_key(master_password: str) -> bytes:
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_text(text: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(text.encode("utf-8"))


def decrypt_text(token: bytes, key: bytes) -> str:
    # token is encrypted bytes stored in DB
    return Fernet(key).decrypt(token).decode("utf-8")


# ----------------------------
# Database Setup
# ----------------------------

DB_PATH = "securevault.db"
db = sqlite3.connect(DB_PATH)
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoveryKey TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    website BLOB NOT NULL,
    username BLOB NOT NULL,
    password BLOB NOT NULL
);
""")

db.commit()


# ----------------------------
# Utility Functions
# ----------------------------

def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def popup(prompt: str) -> str | None:
    # returns None if user cancels
    return simpledialog.askstring("SecureVault", prompt)


def generate_random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))


# ----------------------------
# UI Screens
# ----------------------------

window = tk.Tk()
window.title("SecureVault — Samuel Zizzo")
window.geometry("520x420")


def clear_window() -> None:
    for widget in window.winfo_children():
        widget.destroy()


def new_user_screen() -> None:
    clear_window()

    tk.Label(window, text="SecureVault", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(window, text="Created by Samuel Zizzo", font=("Arial", 10)).pack(pady=2)

    tk.Label(window, text="Create Master Password:").pack()
    pw1 = tk.Entry(window, show="*")
    pw1.pack()

    tk.Label(window, text="Confirm Password:").pack()
    pw2 = tk.Entry(window, show="*")
    pw2.pack()

    msg = tk.Label(window, fg="red")
    msg.pack(pady=5)

    def save_master_password():
        p1 = pw1.get()
        p2 = pw2.get()

        if not p1 or not p2:
            msg.config(text="Password cannot be empty.")
            return
        if p1 != p2:
            msg.config(text="Passwords do not match.")
            return

        hashed = hash_password(p1)
        recovery_plain = uuid.uuid4().hex
        recovery_hashed = hash_password(recovery_plain)

        global encryption_key
        encryption_key = derive_key(p1)

        cursor.execute("DELETE FROM masterpassword")
        cursor.execute(
            "INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)",
            (hashed, recovery_hashed),
        )
        db.commit()

        recovery_screen(recovery_plain)

    tk.Button(window, text="Save Master Password", command=save_master_password).pack(pady=8)


def recovery_screen(recovery_key_plain: str) -> None:
    clear_window()

    tk.Label(window, text="Recovery Key", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(window, text="Save this recovery key somewhere safe.").pack(pady=2)

    key_label = tk.Label(window, text=recovery_key_plain, font=("Consolas", 11))
    key_label.pack(pady=6)

    def copy_key():
        pyperclip.copy(recovery_key_plain)
        messagebox.showinfo("SecureVault", "Recovery key copied to clipboard.")

    tk.Button(window, text="Copy Recovery Key", command=copy_key).pack(pady=5)

    # QR code (kept from your original idea)
    qr = qrcode.make(recovery_key_plain).resize((170, 170))
    qr_img = ImageTk.PhotoImage(qr)
    qr_label = tk.Label(window, image=qr_img)
    qr_label.image = qr_img
    qr_label.pack(pady=10)

    tk.Button(window, text="Continue to Vault", command=password_vault).pack(pady=10)


def login_screen() -> None:
    clear_window()

    tk.Label(window, text="SecureVault Login", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(window, text="Enter Master Password:").pack()

    pw_entry = tk.Entry(window, show="*")
    pw_entry.pack()

    msg = tk.Label(window, fg="red")
    msg.pack(pady=5)

    def check_login():
        pw = pw_entry.get()
        if not pw:
            msg.config(text="Enter your master password.")
            return

        hashed = hash_password(pw)
        cursor.execute("SELECT 1 FROM masterpassword WHERE password=?", (hashed,))
        ok = cursor.fetchone()

        if ok:
            global encryption_key
            encryption_key = derive_key(pw)
            password_vault()
        else:
            msg.config(text="Wrong password.")
            pw_entry.delete(0, tk.END)

    tk.Button(window, text="Login", command=check_login).pack(pady=8)


def password_vault() -> None:
    clear_window()

    if encryption_key is None:
        messagebox.showerror("SecureVault", "Encryption key not set. Please log in again.")
        login_screen()
        return

    tk.Label(window, text="SecureVault", font=("Arial", 16, "bold")).pack(pady=10)

    tree = ttk.Treeview(window, columns=("Website", "Username", "Password"), show="headings")
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def refresh_tree():
        for row in tree.get_children():
            tree.delete(row)

        cursor.execute("SELECT id, website, username, password FROM vault")
        for item_id, site_b, user_b, pass_b in cursor.fetchall():
            tree.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    decrypt_text(site_b, encryption_key),
                    decrypt_text(user_b, encryption_key),
                    decrypt_text(pass_b, encryption_key),
                ),
            )

    def add_entry():
        site = popup("Website:")
        if site is None:
            return

        user = popup("Username:")
        if user is None:
            return

        pw = popup("Password (leave blank to generate):")
        if pw is None:
            return
        if pw.strip() == "":
            pw = generate_random_password()

        site_e = encrypt_text(site, encryption_key)
        user_e = encrypt_text(user, encryption_key)
        pw_e = encrypt_text(pw, encryption_key)

        cursor.execute(
            "INSERT INTO vault(website, username, password) VALUES (?, ?, ?)",
            (site_e, user_e, pw_e),
        )
        db.commit()
        refresh_tree()

    def delete_entry():
        selected = tree.selection()
        if not selected:
            return
        item_id = selected[0]
        cursor.execute("DELETE FROM vault WHERE id=?", (item_id,))
        db.commit()
        refresh_tree()

    def copy_password():
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0], "values")
        if len(values) >= 3:
            pyperclip.copy(values[2])
            messagebox.showinfo("SecureVault", "Password copied to clipboard.")

    btn_row = tk.Frame(window)
    btn_row.pack(pady=6)

    tk.Button(btn_row, text="Add Entry", command=add_entry).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_row, text="Delete Entry", command=delete_entry).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_row, text="Copy Password", command=copy_password).pack(side=tk.LEFT, padx=5)

    refresh_tree()


# ----------------------------
# App Start
# ----------------------------

cursor.execute("SELECT 1 FROM masterpassword LIMIT 1")
exists = cursor.fetchone()

if exists:
    login_screen()
else:
    new_user_screen()

window.mainloop()
db.close()
