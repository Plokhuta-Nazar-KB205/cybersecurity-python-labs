"""Завдання 2: багаторівнева система контролю доступу."""

from __future__ import annotations


def _security_level_name(level: int, security_levels: tuple[str, ...]) -> str:
    # Число 1–4 замінюється назвою з кортежу рівнів.
    return security_levels[level - 1]


def _print_resources(
    resources: list[tuple[str, int]],
    security_levels: tuple[str, ...],
) -> None:
    print("Ресурси системи:")
    for resource_name, resource_level in resources:
        label = _security_level_name(resource_level, security_levels)
        print(f"  - {resource_name}: {label}")
    print()


def _evaluate_access(
    username: str,
    resource_level: int,
    users: dict,
    blocked_users: set[str],
) -> tuple[str, str | None]:
    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    profile = users[username]
    if not profile.get("active", False):
        return "DENY", "Account inactive"

    clearance = profile["clearance"]
    if clearance >= resource_level:
        return "ALLOW", None

    return "DENY", "Insufficient clearance"


def _format_access_line(
    username: str,
    resource_name: str,
    decision: str,
    reason: str | None,
) -> str:
    if decision == "ALLOW":
        return f"user={username} resource={resource_name} -> ALLOW"
    return f"user={username} resource={resource_name} -> DENY ({reason})"


def _print_decisions(
    usernames: list[str],
    users: dict,
    resources: list[tuple[str, int]],
    blocked_users: set[str],
) -> None:
    for username in usernames:
        for resource_name, resource_level in resources:
            decision, reason = _evaluate_access(
                username,
                resource_level,
                users,
                blocked_users,
            )
            print(
                _format_access_line(
                    username,
                    resource_name,
                    decision,
                    reason,
                ),
            )


def run_access_control(
    users: dict,
    resources: list[tuple[str, int]],
    security_levels: tuple[str, ...],
    blocked_users: set[str],
) -> None:
    _print_resources(resources, security_levels)

    print("Перевірка доступу:")
    _print_decisions(list(users), users, resources, blocked_users)

    # Імена з блокування, яких немає в довіднику користувачів.
    missing_users = sorted(name for name in blocked_users if name not in users)
    if missing_users:
        print()
        print("Користувачі, яких немає в системі:")
        _print_decisions(missing_users, users, resources, blocked_users)

    # Єдиний неактивний користувач варіанта також заблокований,
    # тому гілка inactive на цих даних сама не спрацьовує.
    print()
    print("Неактивний обліковий запис поза блокуванням:")
    inactive_users = {
        "inactive_account": {
            "role": "auditor",
            "clearance": 2,
            "department": "Audit",
            "active": False,
        },
    }
    _print_decisions(
        ["inactive_account"],
        inactive_users,
        resources,
        blocked_users,
    )
