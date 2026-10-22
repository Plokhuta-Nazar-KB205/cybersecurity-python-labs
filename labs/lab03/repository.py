"""Параметризовані SQL-запити до бази (без ORM).

Модуль приховує SQLite: помилки бази перетворюються на винятки
репозиторію, тож код поза цим модулем не залежить від sqlite3.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager

from labs.lab03.database import get_connection
from labs.lab03.schemas import RecordCreate, RecordReplace

CATEGORY = "category"
RECORD = "record"


class RepositoryError(Exception):
    """Базовий виняток шару репозиторію."""


class NotFoundError(RepositoryError):
    """Запис або категорію не знайдено (`resource` — CATEGORY чи RECORD)."""

    def __init__(self, resource: str) -> None:
        super().__init__(f"{resource} not found")
        self.resource = resource


class DuplicateError(RepositoryError):
    """Порушення унікальності: код запису або назва категорії."""


class FKConstraintError(RepositoryError):
    """Порушення зовнішнього ключа, зокрема видалення непорожньої категорії."""


@contextmanager
def _translate_errors() -> Iterator[None]:
    """Перетворити помилки sqlite3 на винятки репозиторію."""
    try:
        yield
    except sqlite3.IntegrityError as error:
        message = str(error)
        if "UNIQUE constraint failed" in message:
            raise DuplicateError("unique constraint violated") from error
        if "FOREIGN KEY constraint failed" in message:
            raise FKConstraintError("foreign key violated") from error
        raise RepositoryError("integrity constraint violated") from error
    except sqlite3.Error as error:
        raise RepositoryError("database error") from error


RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, r.value, r.status,"
    " c.name AS category_name"
    " FROM records AS r JOIN categories AS c ON c.id = r.category_id"
)


def _open() -> sqlite3.Connection:
    """Відкрити з’єднання, що повертає рядки як sqlite3.Row."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _fetch_record(
    connection: sqlite3.Connection, record_id: int
) -> dict | None:
    row = connection.execute(
        RECORD_SELECT + " WHERE r.id = ?", (record_id,)
    ).fetchone()
    return dict(row) if row else None


def _record_values(record: RecordCreate) -> tuple:
    return (
        record.code,
        record.title,
        record.category_id,
        record.value,
        record.status,
    )


def _ensure_category(connection: sqlite3.Connection, category_id: int) -> None:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(CATEGORY)


@_translate_errors()
def get_categories() -> list[dict]:
    """Список категорій за зростанням id."""
    with closing(_open()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


@_translate_errors()
def create_category(name: str) -> dict:
    """Створити категорію; дублікат назви дає DuplicateError."""
    with closing(_open()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO categories (name) VALUES (?)", (name,)
        )
        row = connection.execute(
            "SELECT id, name FROM categories WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return dict(row)


@_translate_errors()
def delete_category(category_id: int) -> None:
    """Видалити порожню категорію.

    Якщо категорії немає — NotFoundError; якщо вона містить записи —
    FKConstraintError (ON DELETE RESTRICT).
    """
    with closing(_open()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )
        if cursor.rowcount == 0:
            raise NotFoundError(CATEGORY)


@_translate_errors()
def create_record(record: RecordCreate) -> dict:
    """Створити запис і повернути його разом з category_name.

    Неіснуюча категорія — NotFoundError, дублікат code — DuplicateError.
    """
    with closing(_open()) as connection, connection:
        _ensure_category(connection, record.category_id)
        cursor = connection.execute(
            "INSERT INTO records (code, title, category_id, value, status)"
            " VALUES (?, ?, ?, ?, ?)",
            _record_values(record),
        )
        return _fetch_record(connection, cursor.lastrowid)


@_translate_errors()
def get_record_by_id(record_id: int) -> dict | None:
    """Один запис разом з category_name або None."""
    with closing(_open()) as connection:
        return _fetch_record(connection, record_id)


@_translate_errors()
def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Список записів із фільтрами, об’єднаними через AND, за id ASC."""
    # SQL-фрагменти — лише готові рядки з коду, значення — у params.
    conditions: list[str] = []
    params: list = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    query = RECORD_SELECT
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend((limit, offset))

    with closing(_open()) as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


@_translate_errors()
def update_record(record_id: int, record: RecordReplace) -> dict:
    """Повністю замінити змінювані поля запису.

    Неіснуюча категорія або id — NotFoundError, дублікат code —
    DuplicateError.
    """
    with closing(_open()) as connection, connection:
        _ensure_category(connection, record.category_id)
        cursor = connection.execute(
            "UPDATE records SET code = ?, title = ?, category_id = ?,"
            " value = ?, status = ? WHERE id = ?",
            (*_record_values(record), record_id),
        )
        if cursor.rowcount == 0:
            raise NotFoundError(RECORD)
        return _fetch_record(connection, record_id)


@_translate_errors()
def delete_record(record_id: int) -> None:
    """Видалити запис; NotFoundError, якщо id немає."""
    with closing(_open()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE id = ?", (record_id,)
        )
        if cursor.rowcount == 0:
            raise NotFoundError(RECORD)


@_translate_errors()
def bulk_create_records(records: list[RecordCreate]) -> list[dict]:
    """Створити пакет записів в одній транзакції.

    Неіснуюча категорія — NotFoundError, дублікат code — DuplicateError;
    у будь-якому разі весь пакет скасовується.
    """
    with closing(_open()) as connection, connection:
        for category_id in {record.category_id for record in records}:
            _ensure_category(connection, category_id)
        ids = [
            connection.execute(
                "INSERT INTO records (code, title, category_id, value,"
                " status) VALUES (?, ?, ?, ?, ?)",
                _record_values(record),
            ).lastrowid
            for record in records
        ]
        return [_fetch_record(connection, record_id) for record_id in ids]
