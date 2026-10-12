"""Функции для работы с базой данных SQLite3."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "passwords.db"


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Создаёт таблицы, если их ещё нет."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS master (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entries (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            service  TEXT NOT NULL UNIQUE COLLATE NOCASE,
            login    TEXT NOT NULL,
            password BLOB NOT NULL
        );
        """
    )
    conn.commit()


# --- Мастер-пароль ---

def get_master(conn: sqlite3.Connection):
    """Возвращает (hash, salt) мастер-пароля или None, если он ещё не задан."""
    row = conn.execute("SELECT password_hash, salt FROM master WHERE id = 1").fetchone()
    return (row["password_hash"], row["salt"]) if row else None


def set_master(conn: sqlite3.Connection, password_hash: str, salt: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO master (id, password_hash, salt) VALUES (1, ?, ?)",
        (password_hash, salt),
    )
    conn.commit()


# --- Записи ---

def add_entry(conn: sqlite3.Connection, service: str, login: str, encrypted_password: bytes) -> bool:
    """Добавляет запись. Возвращает False, если запись с таким названием уже есть."""
    try:
        conn.execute(
            "INSERT INTO entries (service, login, password) VALUES (?, ?, ?)",
            (service, login, encrypted_password),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_entry(conn: sqlite3.Connection, service: str):
    return conn.execute(
        "SELECT service, login, password FROM entries WHERE service = ?", (service,)
    ).fetchone()


def list_entries(conn: sqlite3.Connection):
    return conn.execute("SELECT service, login FROM entries ORDER BY service").fetchall()


def delete_entry(conn: sqlite3.Connection, service: str) -> bool:
    """Удаляет запись. Возвращает False, если такой записи не было."""
    cur = conn.execute("DELETE FROM entries WHERE service = ?", (service,))
    conn.commit()
    return cur.rowcount > 0
