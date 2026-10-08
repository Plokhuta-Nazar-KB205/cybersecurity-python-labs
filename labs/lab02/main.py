"""Головний файл лабораторної роботи №2: команди demo та analyze.

Запуск з кореня репозиторію:
    python -m labs.lab02.main demo
    python -m labs.lab02.main analyze --headers-file ...
"""

from __future__ import annotations

import argparse
import time
from datetime import timedelta

from labs.lab02 import task2
from labs.lab02.task1 import Admin, User, UserAccount
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DEMO_PASSWORD = "Str0ng!Pass-2024"


def _section(title: str) -> None:
    line = "=" * len(title)
    print(f"\n{line}\n{title}\n{line}")


def _try_email(user: User, email: str) -> None:
    try:
        user.email = email
    except ValueError as error:
        print(f"  відхилено: {error}")
    else:
        print(f"  прийнято: {user.email}")


def _try_key(account: UserAccount, key: object) -> None:
    try:
        value = account[key]  # type: ignore[index]
    except (KeyError, TypeError, PermissionError) as error:
        print(f"  account[{key!r}] -> {type(error).__name__}: {error}")
    else:
        print(f"  account[{key!r}] -> {type(value).__name__}")


def run_demo() -> int:
    _section("Користувачі та email")
    user = User("analyst", "analyst", "analyst@example.com")
    admin = Admin("root", email="root_admin@corp.example.org")
    print(user)
    rejected = (
        "1bad@example.com",
        "ab@example.com",
        "user@localhost",
        "new.analyst@example.org",
        "new-analyst@example.org",
    )
    for email in rejected:
        print(f"Зміна email на {email!r}:")
        _try_email(user, email)
    print("Зміна email на 'new_analyst@example.org':")
    _try_email(user, "new_analyst@example.org")

    _section("Адміністратор і права")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print(
        "has_permission('manage_users'):", admin.has_permission("manage_users")
    )
    print("has_permission('read_logs'):", admin.has_permission("read_logs"))

    _section("Вхід, сеанс і журнал")
    user.set_password(DEMO_PASSWORD)
    account = UserAccount(user)
    print("Невірний пароль:", account.login("analyst", "wrong", "10.0.0.5"))
    print("Невідомий користувач:", account.login("ghost", "x", "10.0.0.5"))
    print("Автентифікований до входу:", account.is_authenticated())
    ok = account.login("analyst", DEMO_PASSWORD, "10.0.0.5")
    print("Вірний пароль:", ok)
    print("Автентифікований після входу:", account.is_authenticated())
    print(account["session"])

    _section("Доступ через account[...]")
    _try_key(account, "user")
    _try_key(account, "session")
    _try_key(account, "unknown")
    _try_key(account, 42)
    _try_key(account, "__password_hash")
    try:
        account["session"] = "not a session"
    except TypeError as error:
        print(f"  account['session'] = str -> TypeError: {error}")

    _section("Замір таймаутів")
    session = account["session"]
    print("Таймаут 1 с одразу:", session.is_active(1))
    time.sleep(1.2)
    print("Таймаут 1 с через 1.2 с:", session.is_active(1))
    print(f"Таймаут {account.SESSION_TIMEOUT_SEC} с:", session.is_active(900))
    try:
        session.is_active(0)
    except ValueError as error:
        print(f"is_active(0) -> ValueError: {error}")
    session.last_activity -= timedelta(seconds=account.SESSION_TIMEOUT_SEC + 1)
    print("Після простою понад 900 с:", account.is_authenticated())

    account.login("analyst", DEMO_PASSWORD, "10.0.0.5")
    account.logout()
    user.deactivate()
    print(
        "Вхід деактивованого користувача:",
        account.login("analyst", DEMO_PASSWORD, "10.0.0.5"),
    )

    _section("Журнал аудиту")
    account.audit_log.show_all()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2 (варіант 9)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "demo",
        help="демонстрація ООП-моделі із завдання 1",
    )
    analyze = subparsers.add_parser(
        "analyze",
        help="аудит HTTP-заголовків (завдання 2)",
    )
    task2.add_arguments(analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print("Лабораторна робота №2")
    print(
        f"Студент: {STUDENT_NAME}, група {GROUP_NAME}, "
        f"варіант {VARIANT_NUMBER}",
    )
    if args.command == "demo":
        return run_demo()
    return task2.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
