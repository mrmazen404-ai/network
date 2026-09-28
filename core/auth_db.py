# core/auth_db.py
import hashlib
import hmac
import os
import sqlite3
import threading
from datetime import datetime, timedelta

from config import DB_PATH, SESSION_TTL_SECONDS


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return pwd_hash.hex(), salt.hex()


def verify_password(password, stored_hash, stored_salt):
    pwd_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(pwd_hash, stored_hash)


class AuthDatabase:
    _lock = threading.RLock()

    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                pwd_hash TEXT NOT NULL,
                pwd_salt TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                role TEXT DEFAULT 'Administrator',
                avatar_path TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )""")
            cur.execute("PRAGMA table_info(active_sessions)")
            cols = [row[1] for row in cur.fetchall()]
            if "expires_at" not in cols:
                expiry = (datetime.now() + timedelta(seconds=SESSION_TTL_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("ALTER TABLE active_sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT '" + expiry + "'")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_codes(email, used, expires_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON active_sessions(expires_at)")
            self.conn.commit()

    def register_user(self, name, email, password, role=None):
        email = email.strip().lower()
        if len(name.strip()) < 2 or len(password) < 12 or "@" not in email:
            return None
        pwd_hash, pwd_salt = hash_password(password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            try:
                cur = self.conn.cursor()
                if role is None:
                    cur.execute("SELECT COUNT(*) FROM users")
                    role = "Administrator" if cur.fetchone()[0] == 0 else "Viewer"
                cur.execute("""
                INSERT INTO users (name, email, pwd_hash, pwd_salt, is_verified, role, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?)
                """, (name.strip(), email, pwd_hash, pwd_salt, role, now))
                self.conn.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None

    def authenticate_user(self, email, password):
        email = email.strip().lower()
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cur.fetchone()
        if not user:
            return False, "Invalid email or password.", None
        user_dict = dict(user)
        if not verify_password(password, user_dict["pwd_hash"], user_dict["pwd_salt"]):
            return False, "Invalid email or password.", None
        if not user_dict["is_verified"]:
            return False, "Email address not verified yet.", user_dict
        return True, "Login successful!", user_dict

    def mark_email_verified(self, email):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE users SET is_verified=1 WHERE email=?", (email.strip().lower(),))
            self.conn.commit()

    def update_password(self, email, new_password):
        if len(new_password) < 12:
            return False
        pwd_hash, pwd_salt = hash_password(new_password)
        email = email.strip().lower()
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.execute("SELECT id FROM users WHERE email=?", (email,))
                user = cur.fetchone()
                if not user:
                    return False

                cur.execute("UPDATE users SET pwd_hash=?, pwd_salt=? WHERE id=?",
                            (pwd_hash, pwd_salt, user["id"]))
                if cur.rowcount != 1:
                    self.conn.rollback()
                    return False

                # Password changes invalidate every existing session for this user.
                self._revoke_user_sessions_locked(cur, user["id"])
                self.conn.commit()
                return True
            except Exception:
                self.conn.rollback()
                raise

    def change_password(self, email, current_password, new_password):
        user = self.get_user_by_email(email)
        if not user or not verify_password(current_password, user["pwd_hash"], user["pwd_salt"]):
            return False
        return self.update_password(email, new_password)

    def revoke_user_sessions(self, user_id):
        """Revoke all active sessions belonging to one user."""
        with self._lock:
            self._revoke_user_sessions_locked(self.conn.cursor(), user_id)
            self.conn.commit()

    @staticmethod
    def _revoke_user_sessions_locked(cur, user_id):
        cur.execute("DELETE FROM active_sessions WHERE user_id=?", (user_id,))

    def get_user_by_email(self, email):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_profile_name(self, user_id, name):
        name = name.strip()
        if len(name) < 2 or len(name) > 120:
            return False
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE users SET name=? WHERE id=?", (name, user_id))
            self.conn.commit()
            return cur.rowcount == 1

    def delete_unverified_user(self, user_id):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM users WHERE id=? AND is_verified=0", (user_id,))
            self.conn.commit()
            return cur.rowcount == 1

    def store_otp(self, email, code, expires_in_minutes=10):
        email = email.strip().lower()
        expires_at = (datetime.now() + timedelta(minutes=expires_in_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE otp_codes SET used=1 WHERE email=? AND used=0", (email,))
            cur.execute("INSERT INTO otp_codes (email, code, expires_at, used) VALUES (?, ?, ?, 0)",
                        (email, code.strip().upper(), expires_at))
            self.conn.commit()

    def invalidate_otps(self, email):
        with self._lock:
            self.conn.execute("UPDATE otp_codes SET used=1 WHERE email=? AND used=0", (email.strip().lower(),))
            self.conn.commit()

    def verify_otp(self, email, input_code):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
            SELECT * FROM otp_codes
            WHERE email=? AND code=? AND used=0 AND expires_at >= ?
            ORDER BY id DESC LIMIT 1
            """, (email.strip().lower(), input_code.strip().upper(), now_str))
            row = cur.fetchone()
            if not row:
                return False
            cur.execute("UPDATE otp_codes SET used=1 WHERE id=?", (row["id"],))
            self.conn.commit()
            return True

    def create_session(self, user_id):
        token = os.urandom(24).hex()
        now = datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (now + timedelta(seconds=SESSION_TTL_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            # Do not log out unrelated users when this user signs in.
            self._revoke_user_sessions_locked(cur, user_id)
            cur.execute("""
                INSERT INTO active_sessions (user_id, token, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (user_id, token, created_at, expires_at))
            self.conn.commit()
        return token

    def get_current_user_session(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM active_sessions WHERE expires_at < ?", (now,))
            cur.execute("""
            SELECT users.*, active_sessions.expires_at AS session_expires_at
            FROM active_sessions
            JOIN users ON users.id = active_sessions.user_id
            WHERE active_sessions.expires_at >= ?
            ORDER BY active_sessions.id DESC LIMIT 1
            """, (now,))
            row = cur.fetchone()
            self.conn.commit()
            return dict(row) if row else None

    def clear_session(self):
        with self._lock:
            self.conn.execute("DELETE FROM active_sessions")
            self.conn.commit()


# Singleton used by the desktop application.
auth_db = AuthDatabase()
