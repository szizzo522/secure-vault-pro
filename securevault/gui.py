import tkinter as tk
from tkinter import simpledialog, ttk, messagebox

import pyperclip
import qrcode
from PIL import ImageTk

from securevault.config import APP_TITLE, WINDOW_SIZE
from securevault.crypto_utils import derive_key, encrypt_text, decrypt_text
from securevault.db import SecureVaultDB
from securevault.utils import hash_password, generate_recovery_key, generate_random_password


class SecureVaultApp:
    def __init__(self):
        self.db = SecureVaultDB()
        self.encryption_key: bytes | None = None

        self.window = tk.Tk()
        self.window.title(APP_TITLE)
        self.window.geometry(WINDOW_SIZE)

        # Clean shutdown
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- helpers ----------
    def clear_window(self) -> None:
        for widget in self.window.winfo_children():
            widget.destroy()

    def popup(self, prompt: str) -> str | None:
        return simpledialog.askstring("SecureVault", prompt)

    # ---------- screens ----------
    def new_user_screen(self) -> None:
        self.clear_window()

        tk.Label(self.window, text="SecureVault", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(self.window, text="Created by Samuel Zizzo", font=("Arial", 10)).pack(pady=2)

        tk.Label(self.window, text="Create Master Password:").pack()
        pw1 = tk.Entry(self.window, show="*")
        pw1.pack()

        tk.Label(self.window, text="Confirm Password:").pack()
        pw2 = tk.Entry(self.window, show="*")
        pw2.pack()

        msg = tk.Label(self.window, fg="red")
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
            recovery_plain = generate_recovery_key()
            recovery_hashed = hash_password(recovery_plain)

            self.encryption_key = derive_key(p1)
            self.db.set_master_password(hashed, recovery_hashed)

            self.recovery_screen(recovery_plain)

        tk.Button(self.window, text="Save Master Password", command=save_master_password).pack(pady=8)

    def recovery_screen(self, recovery_key_plain: str) -> None:
        self.clear_window()

        tk.Label(self.window, text="Recovery Key", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(self.window, text="Save this recovery key somewhere safe.").pack(pady=2)

        tk.Label(self.window, text=recovery_key_plain, font=("Consolas", 11)).pack(pady=6)

        def copy_key():
            pyperclip.copy(recovery_key_plain)
            messagebox.showinfo("SecureVault", "Recovery key copied to clipboard.")

        tk.Button(self.window, text="Copy Recovery Key", command=copy_key).pack(pady=5)

        qr = qrcode.make(recovery_key_plain).resize((170, 170))
        qr_img = ImageTk.PhotoImage(qr)
        qr_label = tk.Label(self.window, image=qr_img)
        qr_label.image = qr_img
        qr_label.pack(pady=10)

        tk.Button(self.window, text="Continue to Vault", command=self.password_vault).pack(pady=10)

    def login_screen(self) -> None:
        self.clear_window()

        tk.Label(self.window, text="SecureVault Login", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(self.window, text="Enter Master Password:").pack()

        pw_entry = tk.Entry(self.window, show="*")
        pw_entry.pack()

        msg = tk.Label(self.window, fg="red")
        msg.pack(pady=5)

        def check_login():
            pw = pw_entry.get()
            if not pw:
                msg.config(text="Enter your master password.")
                return

            hashed = hash_password(pw)
            ok = self.db.verify_master_password(hashed)

            if ok:
                self.encryption_key = derive_key(pw)
                self.password_vault()
            else:
                msg.config(text="Wrong password.")
                pw_entry.delete(0, tk.END)

        tk.Button(self.window, text="Login", command=check_login).pack(pady=8)

    def password_vault(self) -> None:
        self.clear_window()

        if self.encryption_key is None:
            messagebox.showerror("SecureVault", "Encryption key not set. Please log in again.")
            self.login_screen()
            return

        tk.Label(self.window, text="SecureVault", font=("Arial", 16, "bold")).pack(pady=10)

        tree = ttk.Treeview(self.window, columns=("Website", "Username", "Password"), show="headings")
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def refresh_tree():
            for row in tree.get_children():
                tree.delete(row)

            for item_id, site_b, user_b, pass_b in self.db.list_entries():
                tree.insert(
                    "",
                    "end",
                    iid=item_id,
                    values=(
                        decrypt_text(site_b, self.encryption_key),
                        decrypt_text(user_b, self.encryption_key),
                        decrypt_text(pass_b, self.encryption_key),
                    ),
                )

        def add_entry():
            site = self.popup("Website:")
            if site is None:
                return

            user = self.popup("Username:")
            if user is None:
                return

            pw = self.popup("Password (leave blank to generate):")
            if pw is None:
                return
            if pw.strip() == "":
                pw = generate_random_password()

            site_e = encrypt_text(site, self.encryption_key)
            user_e = encrypt_text(user, self.encryption_key)
            pw_e = encrypt_text(pw, self.encryption_key)

            self.db.add_entry(site_e, user_e, pw_e)
            refresh_tree()

        def delete_entry():
            selected = tree.selection()
            if not selected:
                return
            item_id = int(selected[0])
            self.db.delete_entry(item_id)
            refresh_tree()

        def copy_password():
            selected = tree.selection()
            if not selected:
                return
            values = tree.item(selected[0], "values")
            if len(values) >= 3:
                pyperclip.copy(values[2])
                messagebox.showinfo("SecureVault", "Password copied to clipboard.")

        btn_row = tk.Frame(self.window)
        btn_row.pack(pady=6)

        tk.Button(btn_row, text="Add Entry", command=add_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_row, text="Delete Entry", command=delete_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_row, text="Copy Password", command=copy_password).pack(side=tk.LEFT, padx=5)

        refresh_tree()

    # ---------- lifecycle ----------
    def start(self):
        if self.db.has_master_password():
            self.login_screen()
        else:
            self.new_user_screen()

        self.window.mainloop()

    def on_close(self):
        try:
            self.db.close()
        finally:
            self.window.destroy()


def start_app():
    SecureVaultApp().start()
