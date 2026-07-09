import sqlite3
import os
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get("DATABASE_PATH") or os.path.join(os.path.dirname(__file__), "licenses.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)


def get_db():
    if USE_POSTGRES:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _row_to_dict(row, cursor=None):
    if row is None:
        return None
    if USE_POSTGRES:
        if cursor is None:
            return dict(row)
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))
    return dict(row)


def _execute(conn, sql, params=None):
    if USE_POSTGRES:
        cur = conn.cursor()
        try:
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
        except Exception:
            conn.rollback()
            cur.close()
            raise
        return cur
    if params:
        return conn.execute(sql, params)
    return conn.execute(sql)


def _fetchone(conn, sql, params=None):
    cur = _execute(conn, sql, params)
    row = cur.fetchone()
    if USE_POSTGRES:
        result = _row_to_dict(row, cur)
    else:
        result = _row_to_dict(row)
    cur.close()
    return result


def _fetchall(conn, sql, params=None):
    cur = _execute(conn, sql, params)
    rows = cur.fetchall()
    if USE_POSTGRES:
        result = [_row_to_dict(r, cur) for r in rows]
    else:
        result = [_row_to_dict(r) for r in rows]
    cur.close()
    return result


def _commit(conn):
    if USE_POSTGRES:
        conn.commit()
    else:
        conn.commit()


def _close(conn):
    conn.close()


def init_db():
    conn = get_db()
    try:
        if USE_POSTGRES:
            print(f"[DB] Using PostgreSQL: {DATABASE_URL[:40]}...")
            _execute(conn, """
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT UNIQUE NOT NULL,
                    hwid TEXT,
                    activated_at TEXT,
                    expires_at TEXT,
                    duration_days INTEGER,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_suspended INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            _commit(conn)
            for col in ["is_suspended", "duration_days"]:
                try:
                    _execute(conn, f"ALTER TABLE licenses ADD COLUMN {col} " + ("INTEGER NOT NULL DEFAULT 0" if col == "is_suspended" else "INTEGER"))
                    _commit(conn)
                except Exception:
                    conn.rollback()
        else:
            print(f"[DB] Using SQLite: {DB_PATH}")
            _execute(conn, """
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT UNIQUE NOT NULL,
                    hwid TEXT,
                    activated_at TEXT,
                    expires_at TEXT,
                    duration_days INTEGER,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_suspended INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            _commit(conn)
            for col in ["is_suspended", "duration_days"]:
                try:
                    _execute(conn, f"ALTER TABLE licenses ADD COLUMN {col} " + ("INTEGER NOT NULL DEFAULT 0" if col == "is_suspended" else "INTEGER"))
                    _commit(conn)
                except Exception:
                    pass
        # Log total key count
        count = _fetchone(conn, "SELECT COUNT(*) as cnt FROM licenses")
        print(f"[DB] Licenses in database: {count['cnt'] if count else 0}")
    finally:
        _close(conn)


def create_license_key(days=None):
    import secrets
    import string
    key = "MUSRUS-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat() if days else None

    conn = get_db()
    try:
        _execute(conn, "INSERT INTO licenses (license_key, created_at, expires_at, duration_days) VALUES (%s, %s, %s, %s)" if USE_POSTGRES
                 else "INSERT INTO licenses (license_key, created_at, expires_at, duration_days) VALUES (?, ?, ?, ?)",
                 (key, now, expires, days))
        _commit(conn)
        row = _fetchone(conn, "SELECT * FROM licenses WHERE license_key = %s" if USE_POSTGRES else "SELECT * FROM licenses WHERE license_key = ?", (key,))
        print(f"[DB] Created key: {key}")
        return dict(row) if row else {"license_key": key}
    except Exception as e:
        print(f"[DB] Failed to create key: {e}")
        return {"success": False, "error": "create_failed", "message": str(e)}
    finally:
        _close(conn)


def get_license(license_key):
    conn = get_db()
    try:
        return _fetchone(conn, "SELECT * FROM licenses WHERE license_key = %s" if USE_POSTGRES else "SELECT * FROM licenses WHERE license_key = ?", (license_key,))
    finally:
        _close(conn)


def activate_license(license_key, hwid):
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    if not lic["is_active"]:
        return {"success": False, "error": "revoked", "message": "Ключ отозван"}
    if lic["is_suspended"]:
        return {"success": False, "error": "suspended", "message": "Ключ приостановлен. Обратитесь к разработчику."}
    if lic["expires_at"]:
        expires = datetime.fromisoformat(lic["expires_at"])
        if expires < datetime.now(timezone.utc):
            return {"success": False, "error": "expired", "message": "Срок действия ключа истёк"}

    existing_hwid = lic["hwid"]
    if existing_hwid and existing_hwid != hwid:
        return {"success": False, "error": "already_used", "message": "Ключ уже активирован на другом устройстве. Требуется сброс HWID."}

    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        if not lic["activated_at"] and lic["duration_days"]:
            expires = (datetime.now(timezone.utc) + timedelta(days=lic["duration_days"])).isoformat()
            _execute(conn, "UPDATE licenses SET hwid = %s, activated_at = %s, expires_at = %s WHERE license_key = %s" if USE_POSTGRES
                     else "UPDATE licenses SET hwid = ?, activated_at = ?, expires_at = ? WHERE license_key = ?",
                     (hwid, now, expires, license_key))
        else:
            _execute(conn, "UPDATE licenses SET hwid = %s, activated_at = COALESCE(activated_at, %s) WHERE license_key = %s" if USE_POSTGRES
                     else "UPDATE licenses SET hwid = ?, activated_at = COALESCE(activated_at, ?) WHERE license_key = ?",
                     (hwid, now, license_key))
        _commit(conn)
    finally:
        _close(conn)

    if existing_hwid == hwid:
        return {"success": True, "message": "Ключ уже активирован на этом устройстве"}
    return {"success": True, "message": "Активация успешна"}


def verify_license(license_key, hwid):
    lic = get_license(license_key)
    if not lic:
        return {"valid": False, "error": "not_found", "message": "Ключ не найден"}
    if not lic["is_active"]:
        return {"valid": False, "error": "revoked", "message": "Ключ отозван"}
    if lic["is_suspended"]:
        return {"valid": False, "error": "suspended", "message": "Ключ приостановлен. Обратитесь к разработчику."}
    if lic["expires_at"]:
        expires = datetime.fromisoformat(lic["expires_at"])
        if expires < datetime.now(timezone.utc):
            return {"valid": False, "error": "expired", "message": "Срок действия ключа истёк"}
    if not lic["hwid"]:
        return {"valid": False, "error": "not_activated", "message": "Ключ ещё не активирован"}
    if lic["hwid"] != hwid:
        return {"valid": False, "error": "already_used", "message": "Ключ уже используется на другом устройстве. Чтобы сбросить привязку, приобретите сброс HWID за 199\u20bd."}
    return {"valid": True, "message": "Ключ действителен"}


def reset_hwid(license_key):
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    conn = get_db()
    try:
        _execute(conn, "UPDATE licenses SET hwid = NULL, activated_at = NULL WHERE license_key = %s" if USE_POSTGRES
                 else "UPDATE licenses SET hwid = NULL, activated_at = NULL WHERE license_key = ?", (license_key,))
        _commit(conn)
        return {"success": True, "message": "HWID сброшен"}
    finally:
        _close(conn)


def revoke_license(license_key):
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    conn = get_db()
    try:
        _execute(conn, "UPDATE licenses SET is_active = 0 WHERE license_key = %s" if USE_POSTGRES
                 else "UPDATE licenses SET is_active = 0 WHERE license_key = ?", (license_key,))
        _commit(conn)
        return {"success": True, "message": "Ключ отозван"}
    finally:
        _close(conn)


def suspend_license(license_key):
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    conn = get_db()
    try:
        _execute(conn, "UPDATE licenses SET is_suspended = 1 WHERE license_key = %s" if USE_POSTGRES
                 else "UPDATE licenses SET is_suspended = 1 WHERE license_key = ?", (license_key,))
        _commit(conn)
        return {"success": True, "message": "Ключ приостановлен"}
    finally:
        _close(conn)


def resume_license(license_key):
    lic = get_license(license_key)
    if not lic:
        return {"success": False, "error": "not_found", "message": "Ключ не найден"}
    conn = get_db()
    try:
        _execute(conn, "UPDATE licenses SET is_suspended = 0 WHERE license_key = %s" if USE_POSTGRES
                 else "UPDATE licenses SET is_suspended = 0 WHERE license_key = ?", (license_key,))
        _commit(conn)
        return {"success": True, "message": "Ключ возобновлён"}
    finally:
        _close(conn)


def get_all_licenses():
    conn = get_db()
    try:
        return _fetchall(conn, "SELECT * FROM licenses ORDER BY id DESC")
    finally:
        _close(conn)


def delete_license(license_key):
    conn = get_db()
    try:
        before = _fetchone(conn, "SELECT COUNT(*) as cnt FROM licenses WHERE license_key = %s" if USE_POSTGRES
                          else "SELECT COUNT(*) as cnt FROM licenses WHERE license_key = ?", (license_key,))
        cur = _execute(conn, "DELETE FROM licenses WHERE license_key = %s" if USE_POSTGRES
                       else "DELETE FROM licenses WHERE license_key = ?", (license_key,))
        deleted = cur.rowcount
        _commit(conn)
        after = _fetchone(conn, "SELECT COUNT(*) as cnt FROM licenses WHERE license_key = %s" if USE_POSTGRES
                         else "SELECT COUNT(*) as cnt FROM licenses WHERE license_key = ?", (license_key,))
        print(f"[DB] delete_license({license_key}): before={before['cnt'] if before else 0}, deleted={deleted}, after={after['cnt'] if after else 0}")
        if deleted == 0:
            return {"success": False, "error": "not_found", "message": "Ключ не найден"}
        return {"success": True, "message": "Ключ удалён"}
    finally:
        _close(conn)


def clear_all_licenses():
    conn = get_db()
    try:
        before = _fetchone(conn, "SELECT COUNT(*) as cnt FROM licenses")
        _execute(conn, "DELETE FROM licenses")
        _commit(conn)
        after = _fetchone(conn, "SELECT COUNT(*) as cnt FROM licenses")
        print(f"[DB] clear_all_licenses: before={before['cnt'] if before else 0}, after={after['cnt'] if after else 0}")
        return {"success": True, "message": "Все ключи удалены"}
    finally:
        _close(conn)
