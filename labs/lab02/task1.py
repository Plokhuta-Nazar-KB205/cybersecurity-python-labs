"""Завдання 1: ООП-модель користувачів, сеансів і журналу аудиту."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar

# Локальна частина: літера + ще 2–63 символи (літери, цифри, "_"),
# разом 3–64. Домен: мітки через крапку, мінімум одна крапка.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}",
)
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16


class User:
    """Користувач із валідованим email і хешем пароля (PBKDF2)."""

    def __init__(
        self,
        username: str,
        role: str,
        email: str | None = None,
        active: bool = True,
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""
        self._email: str | None = None
        if email is not None:
            self.email = email

    @property
    def email(self) -> str | None:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    @staticmethod
    def _derive_hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            iterations=PBKDF2_ITERATIONS,
        )

    def set_password(self, password: str) -> None:
        # Відкритий пароль не зберігається: лише сіль і хеш.
        salt = os.urandom(SALT_SIZE)
        self.__password_salt = salt
        self.__password_hash = self._derive_hash(password, salt)

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            return False
        candidate = self._derive_hash(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return (
            f"User(username={self.username}, role={self.role}, "
            f"email={self.email}, {state})"
        )


class Admin(User):
    """Адміністратор: користувач із набором прав."""

    def __init__(
        self,
        username: str,
        role: str = "admin",
        email: str | None = None,
        active: bool = True,
        permissions: set[str] | list[str] | None = None,
    ) -> None:
        super().__init__(username, role, email, active)
        # None замість змінюваного значення за замовчуванням.
        self.permissions: set[str] = set(permissions or ())

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        granted = ", ".join(sorted(self.permissions)) or "-"
        return f"{super().__str__()} permissions=[{granted}]"


class Session:
    """Сеанс користувача; усі позначки часу — в UTC."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути більшим за 0")
        idle = datetime.now(timezone.utc) - self.last_activity
        return idle.total_seconds() <= timeout_sec

    def __str__(self) -> str:
        return (
            f"Session(ip={self.ip}, "
            f"login_time={self.login_time.isoformat()}, "
            f"last_activity={self.last_activity.isoformat()})"
        )


@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str

    def __str__(self) -> str:
        return (
            f"{self.timestamp.isoformat()} | {self.username} | {self.action}"
        )


class AuditLog:
    """Журнал подій входу/виходу. Паролі в нього не потрапляють."""

    ALLOWED_ACTIONS = ("login_success", "login_failure", "logout")

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        if action not in self.ALLOWED_ACTIONS:
            raise ValueError(f"Невідома подія аудиту: {action!r}")
        self.entries.append(
            AuditEntry(datetime.now(timezone.utc), username, action),
        )

    def show_all(self) -> None:
        if not self.entries:
            print("Журнал аудиту порожній.")
            return
        for entry in self.entries:
            print(entry)


class UserAccount:
    """Композиція User + Session (опціонально) + AuditLog."""

    SESSION_TIMEOUT_SEC = 900
    # Ключі, доступні через account[...], і допустимі типи значень.
    _EXPOSED_TYPES: ClassVar[dict[str, tuple[type, ...]]] = {
        "user": (User,),
        "session": (Session, type(None)),
        "audit_log": (AuditLog,),
    }

    def __init__(
        self,
        user: User,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        ok = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not ok:
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if not self.session.is_active(self.SESSION_TIMEOUT_SEC):
            # Прострочений сеанс не подовжується.
            return False
        self.session.touch()
        return True

    def logout(self) -> None:
        if self.session is None:
            return
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def _check_key(self, key: object) -> str:
        if not isinstance(key, str):
            raise TypeError(
                f"Ключ має бути str, а не {type(key).__name__}",
            )
        if "password" in key.lower():
            raise PermissionError(f"Доступ до {key!r} заборонено")
        if key not in self._EXPOSED_TYPES:
            raise KeyError(key)
        return key

    def __getitem__(self, key: str) -> object:
        return getattr(self, self._check_key(key))

    def __setitem__(self, key: str, value: object) -> None:
        name = self._check_key(key)
        expected = self._EXPOSED_TYPES[name]
        if not isinstance(value, expected):
            raise TypeError(
                f"Для {name!r} очікується {expected[0].__name__}, "
                f"а не {type(value).__name__}",
            )
        setattr(self, name, value)
