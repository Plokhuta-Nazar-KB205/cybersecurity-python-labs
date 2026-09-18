"""Завдання 3: хешування, CSV-база та JSON-логування."""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_CSV_PATH = DATA_DIR / "users.csv"
LOG_JSON_PATH = DATA_DIR / "log.json"

users_db: list[tuple[str, str]] = []

HASH_ALGORITHM = "sha224"
MIN_PASSWORD_LENGTH = 13
PERSONAL_SALT = "00009"


class ValidationError(Exception):
    """Пароль коротший за мінімум варіанта."""


def configure_auth(
    hash_algorithm: str,
    min_password_length: int,
    personal_salt: str,
) -> None:
    global HASH_ALGORITHM, MIN_PASSWORD_LENGTH, PERSONAL_SALT
    HASH_ALGORITHM = hash_algorithm
    MIN_PASSWORD_LENGTH = min_password_length
    PERSONAL_SALT = personal_salt


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or password == "" or salt is None or salt == "":
        raise ValueError("Пароль і сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            "Пароль коротший за мінімум "
            f"{MIN_PASSWORD_LENGTH} символів для варіанту",
        )

    digest = hashlib.new(HASH_ALGORITHM)
    digest.update(f"{password}{salt}".encode())
    return digest.hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(
    users_list: tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rows = [
        create_user(username, password) for username, password in users_list
    ]
    with USERS_CSV_PATH.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(rows)


def load_users_db() -> list[tuple[str, str]]:
    global users_db
    loaded: list[tuple[str, str]] = []
    with USERS_CSV_PATH.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if len(row) >= 2:
                loaded.append((row[0], row[1]))
    users_db = loaded
    return users_db


def _print_users_table(records: list[tuple[str, str]]) -> None:
    headers = ("Логін", "Хеш пароля")
    login_width = max(
        len(headers[0]),
        *(len(login) for login, _ in records),
        0,
    )
    hash_width = max(
        len(headers[1]),
        *(len(hash_value) for _, hash_value in records),
        0,
    )
    widths = (login_width, hash_width)

    def fmt_line(cells: tuple[str, str]) -> str:
        return f"| {cells[0]:<{widths[0]}} | {cells[1]:<{widths[1]}} |"

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    print(separator)
    print(fmt_line(headers))
    print(separator)
    for login, hash_value in records:
        print(fmt_line((login, hash_value)))
    print(separator)


def _append_log_entry(
    username: str,
    result: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).astimezone()
    timestamp_text = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "event": "login",
        "user": username,
        "result": result,
        "timestamp": timestamp_text,
        "args": list(args),
        "kwargs": kwargs,
    }

    events: list[dict[str, Any]] = []
    if LOG_JSON_PATH.exists():
        with LOG_JSON_PATH.open(encoding="utf-8") as log_file:
            try:
                events = json.load(log_file)
            except json.JSONDecodeError:
                events = []

    events.append(entry)
    with LOG_JSON_PATH.open("w", encoding="utf-8") as log_file:
        json.dump(events, log_file, ensure_ascii=False, indent=2)


def log_event(func: Callable[..., bool]) -> Callable[..., bool]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> bool:
        username = args[0] if args else str(kwargs.get("username", ""))
        try:
            success = func(*args, **kwargs)
        except (ValueError, ValidationError):
            _append_log_entry(username, "failure", args, kwargs)
            raise

        result_label = "success" if success else "failure"
        _append_log_entry(username, result_label, args, kwargs)
        return success

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    missing_username = username is None or username == ""
    missing_password = password is None or password == ""
    if missing_username or missing_password:
        raise ValueError("Логін і пароль не можуть бути порожніми")

    expected_hash = generate_hash(password, PERSONAL_SALT)
    for stored_login, stored_hash in users_db:
        if stored_login == username:
            return stored_hash == expected_hash
    return False


def run_auth_workflow(
    hash_algorithm: str,
    min_password_length: int,
    personal_salt: str,
    users_to_register: tuple[tuple[str, str], ...],
) -> None:
    # Файли, валідація та вхід перехоплюються в одному сценарії.
    try:
        configure_auth(hash_algorithm, min_password_length, personal_salt)

        print(
            f"Алгоритм хешування: {HASH_ALGORITHM}, "
            f"мін. довжина пароля: {MIN_PASSWORD_LENGTH}, "
            f"сіль: {PERSONAL_SALT}",
        )

        create_users(users_to_register)
        records = load_users_db()
        print("\nБаза користувачів (users.csv):")
        _print_users_table(records)

        print("\nСпроби автентифікації:")
        demo_attempts = (
            (
                "cloud_architect",
                "CloudVault@Secure13",
                "коректні облікові дані",
            ),
            (
                "cloud_architect",
                "WrongPassword!!!",
                "невірний пароль",
            ),
            (
                "unknown_user",
                "CloudVault@Secure13",
                "невідомий логін",
            ),
        )
        for username, password, description in demo_attempts:
            try:
                result = login(username, password)
                print(
                    f"  [{description}] "
                    f"login('{username}', '***') -> {result}",
                )
            except (ValueError, ValidationError) as error:
                print(f"  [{description}] помилка: {error}")

        try:
            login("", "CloudVault@Secure13")
        except ValueError as error:
            print(
                f"  [порожній логін] перехоплено ValueError: {error}",
            )

        try:
            login("cloud_architect", "Short#Pass1")
        except ValidationError as error:
            print(
                f"  [короткий пароль] перехоплено ValidationError: {error}",
            )
    except FileNotFoundError as error:
        # Файл бази або журналу відсутній.
        print(f"File not found: {error}")
    except PermissionError as error:
        # Недостатньо прав для читання або запису.
        print(f"Permission denied: {error}")
    except IOError as error:  # noqa: UP024
        # Методичка вимагає саме ім'я IOError.
        print(f"I/O error: {error}")
    except ValidationError as error:
        # Пароль не відповідає політиці довжини.
        print(f"Password validation error: {error}")
    except ValueError as error:
        # Порожні дані або некоректний алгоритм хешування.
        print(f"Invalid input: {error}")
