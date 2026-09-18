"""Завдання 1: комплексний аналізатор надійності паролів."""

from __future__ import annotations

import random
from collections.abc import Iterable

LEVEL_FORBIDDEN = "Заборонений"
LEVEL_WEAK = "Слабкий"
LEVEL_MEDIUM = "Середній"
LEVEL_STRONG = "Сильний"
LEVEL_VERY_STRONG = "Дуже сильний"


def _has_digit(password: str) -> bool:
    return any(char.isdigit() for char in password)


def _has_upper(password: str) -> bool:
    return any(char.isupper() for char in password)


def _has_special(password: str) -> bool:
    # Спецсимвол — будь-який нелітеральний і нецифровий знак.
    return any(not char.isalnum() for char in password)


def _has_lower(password: str) -> bool:
    return any(char.islower() for char in password)


def _required_checks(criteria: dict) -> list[tuple[str, bool]]:
    """Повертає активні вимоги та функції їх перевірки."""
    mapping = [
        ("require_digits", _has_digit),
        ("require_upper", _has_upper),
        ("require_special", _has_special),
    ]
    checks: list[tuple[str, bool]] = []
    for key, checker in mapping:
        if criteria.get(key):
            checks.append((key, checker))
    return checks


def _count_met_policy(password: str, criteria: dict) -> tuple[int, int]:
    checks = _required_checks(criteria)
    if not checks:
        return 0, 0
    met = sum(1 for _, checker in checks if checker(password))
    return met, len(checks)


def classify_password(
    password: str,
    criteria: dict,
    forbidden_passwords: set[str],
    all_passwords: Iterable[str],
) -> str:
    """Повертає рівень надійності за правилами методички."""
    min_length = criteria["min_length"]

    if password in forbidden_passwords or len(password) < min_length:
        return LEVEL_FORBIDDEN

    met, total = _count_met_policy(password, criteria)
    all_policy_met = total > 0 and met == total
    very_strong_length = min_length + 4
    # Унікальність рахується вже після доданих дублікатів.
    is_unique = list(all_passwords).count(password) == 1

    if all_policy_met and len(password) >= very_strong_length and is_unique:
        return LEVEL_VERY_STRONG

    # «Сильний»: усі критерії і довжина менша за min_length + 4.
    if all_policy_met and len(password) < very_strong_length:
        return LEVEL_STRONG

    if len(password) >= min_length and 0 < met < total:
        return LEVEL_MEDIUM

    # Повний довгий пароль без унікальності сюди не входить:
    # він не «сильний» і не «дуже сильний», тож лишається слабким.
    return LEVEL_WEAK


def simulate_password_reuse(
    passwords: list[str],
) -> tuple[list[str], list[int]]:
    """Додає копії паролів за трьома випадковими індексами."""
    if not passwords:
        return passwords, []

    population = range(len(passwords))
    # Три різні індекси, якщо у списку достатньо паролів.
    if len(passwords) >= 3:
        picked_indices = random.sample(population, 3)
    else:
        picked_indices = [random.choice(population) for _ in range(3)]

    extended = passwords + [passwords[index] for index in picked_indices]
    return extended, picked_indices


def _print_table(rows: list[tuple[int, str, str]]) -> None:
    headers = ("№", "Пароль", "Рівень надійності")
    widths = [
        max(len(headers[0]), *(len(str(row[0])) for row in rows)),
        max(len(headers[1]), *(len(row[1]) for row in rows)),
        max(len(headers[2]), *(len(row[2]) for row in rows)),
    ]

    def fmt_line(cells: tuple[str, str, str]) -> str:
        return (
            f"| {cells[0]:<{widths[0]}} | "
            f"{cells[1]:<{widths[1]}} | "
            f"{cells[2]:<{widths[2]}} |"
        )

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    print(separator)
    print(fmt_line(headers))
    print(separator)
    for index, password, level in rows:
        print(fmt_line((str(index), password, level)))
    print(separator)


def run_password_analysis(
    passwords: list[str],
    criteria: dict,
    forbidden_passwords: set[str],
) -> None:
    base_passwords = list(passwords)
    passwords_with_reuse, reuse_indices = simulate_password_reuse(
        base_passwords,
    )

    print(
        "Індекси для імітації повторного використання паролів:",
        ", ".join(str(i) for i in reuse_indices),
    )
    print()

    rows: list[tuple[int, str, str]] = []
    for position, password in enumerate(passwords_with_reuse, start=1):
        level = classify_password(
            password,
            criteria,
            forbidden_passwords,
            passwords_with_reuse,
        )
        rows.append((position, password, level))

    _print_table(rows)
