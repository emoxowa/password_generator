"""CLI менеджер паролей.

Использование:
    python main.py add       — добавить запись
    python main.py get       — показать пароль по названию
    python main.py list      — список записей (названия и логины)
    python main.py delete    — удалить запись по названию
    python main.py new       — сгенерировать новый пароль (и при желании сохранить)
"""

import argparse
import shutil
import subprocess
import sys
from getpass import getpass

from cryptography.fernet import Fernet, InvalidToken

import crypto
import db

MAX_LOGIN_ATTEMPTS = 3

# Системные утилиты буфера обмена: macOS, Windows, Linux (Wayland / X11)
CLIPBOARD_COMMANDS = [
    ["pbcopy"],
    ["clip"],
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
]


def copy_to_clipboard(text: str) -> bool:
    """Копирует текст в буфер обмена. Возвращает False, если утилита не найдена."""
    for cmd in CLIPBOARD_COMMANDS:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), check=True)
                return True
            except (OSError, subprocess.CalledProcessError):
                continue
    return False


def report_copy(password: str) -> None:
    if copy_to_clipboard(password):
        print("Пароль скопирован в буфер обмена.")
    else:
        print("Буфер обмена недоступен — скопируйте пароль из терминала вручную.")


# --- Вход ---

def setup_master(conn) -> None:
    print("Первый запуск. Придумайте мастер-пароль.")
    while True:
        password = getpass("Мастер-пароль: ")
        if len(password) < 4:
            print("Слишком короткий пароль (минимум 4 символа).")
            continue
        if getpass("Повторите мастер-пароль: ") != password:
            print("Пароли не совпадают, попробуйте ещё раз.")
            continue
        break
    password_hash, salt = crypto.hash_password(password)
    db.set_master(conn, password_hash, salt)
    print("Мастер-пароль сохранён.\n")


def login(conn) -> bool:
    master = db.get_master(conn)
    if master is None:
        setup_master(conn)
        return True
    stored_hash, salt = master
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        if crypto.verify_password(getpass("Введите мастер-пароль: "), stored_hash, salt):
            return True
        print(f"Неверный пароль ({attempt}/{MAX_LOGIN_ATTEMPTS}).")
    return False


# --- Команды ---

def ask(prompt: str) -> str:
    """Запрашивает непустую строку."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Значение не может быть пустым.")


def ask_length(default: int = 16) -> int:
    while True:
        raw = input(f"Длина пароля [{default}]: ").strip()
        if not raw:
            return default
        if raw.isdigit() and 4 <= int(raw) <= 128:
            return int(raw)
        print("Введите число от 4 до 128.")


def save_entry(conn, fernet, service: str, login_name: str, password: str) -> None:
    if db.add_entry(conn, service, login_name, crypto.encrypt(fernet, password)):
        print(f"Запись «{service}» сохранена.")
    else:
        print(f"Запись «{service}» уже существует. Удалите её командой delete, чтобы перезаписать.")


def cmd_add(conn, fernet) -> None:
    service = ask("Название (откуда): ")
    login_name = ask("Логин: ")
    password = getpass("Пароль (оставьте пустым, чтобы сгенерировать): ")
    if not password:
        password = crypto.generate_password(ask_length())
        print(f"Сгенерирован пароль: {password}")
    save_entry(conn, fernet, service, login_name, password)


def cmd_get(conn, fernet) -> None:
    service = ask("Название: ")
    entry = db.get_entry(conn, service)
    if entry is None:
        print(f"Запись «{service}» не найдена.")
        return
    try:
        password = crypto.decrypt(fernet, entry["password"])
    except InvalidToken:
        print("Не удалось расшифровать пароль: файл .key не подходит к этой базе.")
        return
    print(f"Название: {entry['service']}")
    print(f"Логин:    {entry['login']}")
    print(f"Пароль:   {password}")
    report_copy(password)


def cmd_list(conn, fernet) -> None:
    entries = db.list_entries(conn)
    if not entries:
        print("Записей пока нет.")
        return
    width = max(len("Название"), *(len(e["service"]) for e in entries))
    print(f"{'Название'.ljust(width)}  Логин")
    print(f"{'-' * width}  {'-' * 20}")
    for e in entries:
        print(f"{e['service'].ljust(width)}  {e['login']}")


def cmd_delete(conn, fernet) -> None:
    service = ask("Название записи для удаления: ")
    if db.get_entry(conn, service) is None:
        print(f"Запись «{service}» не найдена.")
        return
    if input(f"Удалить «{service}»? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
        print("Отменено.")
        return
    db.delete_entry(conn, service)
    print(f"Запись «{service}» удалена.")


def cmd_new(conn, fernet) -> None:
    password = crypto.generate_password(ask_length())
    print(f"Новый пароль: {password}")
    report_copy(password)
    if input("Сохранить его? [y/N]: ").strip().lower() in ("y", "yes", "д", "да"):
        save_entry(conn, fernet, ask("Название (откуда): "), ask("Логин: "), password)


COMMANDS = {
    "add": (cmd_add, "добавить новую запись"),
    "get": (cmd_get, "получить пароль по названию"),
    "list": (cmd_list, "показать все записи (названия и логины)"),
    "delete": (cmd_delete, "удалить запись по названию"),
    "new": (cmd_new, "сгенерировать новый пароль"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Менеджер паролей с шифрованием.")
    sub = parser.add_subparsers(dest="command", required=True, metavar="КОМАНДА")
    for name, (_, help_text) in COMMANDS.items():
        sub.add_parser(name, help=help_text)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    conn = db.get_connection()
    try:
        db.init_db(conn)
        if not login(conn):
            print("Доступ запрещён.")
            return 1
        fernet = Fernet(crypto.load_or_create_key())
        handler, _ = COMMANDS[args.command]
        handler(conn, fernet)
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nПрервано.")
        return 130
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
