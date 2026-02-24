import sqlite3
from typing import Optional, Iterable, Tuple

from securevault.config import DB_PATH


class SecureVaultDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cur = self.conn.cursor()
        self._init_tables()

    def _init_tables(self) -> None:
        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS masterpassword(
            id INTEGER PRIMARY KEY,
            password TEXT NOT NULL,
            recoveryKey TEXT NOT NULL
        );
        """)

        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS vault(
            id INTEGER PRIMARY KEY,
            website BLOB NOT NULL,
            username BLOB NOT NULL,
            password BLOB NOT NULL
        );
        """)
        self.conn.commit()

    # ---------- master password ----------
    def has_master_password(self) -> bool:
        self.cur.execute("SELECT 1 FROM masterpassword LIMIT 1")
        return self.cur.fetchone() is not None

    def set_master_password(self, hashed_password: str, hashed_recovery: str) -> None:
        self.cur.execute("DELETE FROM masterpassword")
        self.cur.execute(
            "INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)",
            (hashed_password, hashed_recovery),
        )
        self.conn.commit()

    def verify_master_password(self, hashed_password: str) -> bool:
        self.cur.execute("SELECT 1 FROM masterpassword WHERE password=?", (hashed_password,))
        return self.cur.fetchone() is not None

    # ---------- vault entries ----------
    def list_entries(self):
        self.cur.execute("SELECT id, website, username, password FROM vault")
        return self.cur.fetchall()

    def add_entry(self, site_b: bytes, user_b: bytes, pass_b: bytes) -> None:
        self.cur.execute(
            "INSERT INTO vault(website, username, password) VALUES (?, ?, ?)",
            (site_b, user_b, pass_b),
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int) -> None:
        self.cur.execute("DELETE FROM vault WHERE id=?", (entry_id,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
