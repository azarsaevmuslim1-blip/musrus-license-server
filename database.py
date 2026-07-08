import sqlite3
import os
from datetime import datetime, timedelta, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "licenses.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            activated_at TEXT,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def create_license_key(days: int | None = None) -> dict:
    import secrets, string
    key = "MUSRUS-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat() if days else None

    conn = get_db()
    conn.execute(
        "INSERT INTO licenses (license_key, created_at, expires_at) VALUES (?, ?, ?)",
        (key, now, expires),
    )
    conn.commit()
    # read back
    row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (key,)).fetchone()
    conn.close()
    return dict(row) if row else {"license_key": key}


def get_license(license_key: str) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    conn.close()
    return dict(row) if row else None


def activate_license(license_key: str, hwid: str) -> dict:
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}

    if not lic["is_active"]:
        return {"success": False, "error": "revoked", "message": "Ключ отозван"}

    if lic["expires_at"]:
        expires = datetime.fromisoformat(lic["expires_at"])
        if expires < datetime.now(timezone.utc):
            return {"success": False, "error": "expired", "message": "Срок действия ключа истёк"}

    existing_hwid = lic["hwid"]
    if existing_hwid and existing_hwid != hwid:
        return {
            "success": False,
            "error": "already_used",
            "message": "Ключ уже активирован на другом устройстве. Требуется сброс HWID.",
        }

    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE licenses SET hwid = ?, activated_at = COALESCE(activated_at, ?) WHERE license_key = ?",
        (hwid, now, license_key),
    )
    conn.commit()
    conn.close()

    if existing_hwid == hwid:
        return {"success": True, "message": "Ключ уже активирован на этом устройстве"}
    return {"success": True, "message": "Активация успешна"}


def verify_license(license_key: str, hwid: str) -> dict:
    lic = get_license(license_key)
    if not lic:
        return {"valid": False, "error": "not_found", "message": "Ключ не найден"}

    if not lic["is_active"]:
        return {"valid": False, "error": "revoked", "message": "Ключ отозван"}

    if lic["expires_at"]:
        expires = datetime.fromisoformat(lic["expires_at"])
        if expires < datetime.now(timezone.utc):
            return {"valid": False, "error": "expired", "message": "Срок действия ключа истёк"}

    if not lic["hwid"]:
        return {"valid": False, "error": "not_activated", "message": "Ключ ещё не активирован"}

    if lic["hwid"] != hwid:
        return {
            "valid": False,
            "error": "already_used",
            "message": "Ключ уже используется на другом устройстве. Чтобы сбросить привязку, приобретите сброс HWID за 199\u20bd.",
        }

    return {"valid": True, "message": "Ключ действителен"}


def reset_hwid(license_key: str) -> dict:
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}

    conn = get_db()
    conn.execute("UPDATE licenses SET hwid = NULL, activated_at = NULL WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "HWID сброшен"}


def revoke_license(license_key: str) -> dict:
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}

    conn = get_db()
    conn.execute("UPDATE licenses SET is_active = 0 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Ключ отозван"}


def get_all_licenses() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_license(license_key: str) -> dict:
    conn = get_db()
    cur = conn.execute("DELETE FROM licenses WHERE license_key = ?", (license_key,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    if deleted == 0:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    return {"success": True, "message": "Ключ удалён"}


def clear_all_licenses() -> dict:
    conn = get_db()
    conn.execute("DELETE FROM licenses")
    conn.commit()
    conn.close()
    return {"success": True, "message": "Все ключи удалены"}
