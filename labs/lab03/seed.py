"""Початкове заповнення бази даними з data/seed.json."""

import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def load_seed(path: Path = SEED_PATH) -> dict:
    """Прочитати JSON і перевірити його структуру."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("seed.json має бути об’єктом")
    for key in ("categories", "records"):
        items = data.get(key)
        if not isinstance(items, list) or not items:
            raise TypeError(f"поле {key!r} має бути непорожнім масивом")
        if not all(isinstance(item, dict) for item in items):
            raise TypeError(f"елементи {key!r} мають бути об’єктами")
    for item in data["categories"]:
        if set(item) != {"id", "name"}:
            raise ValueError(f"Некоректна категорія: {item!r}")
    for item in data["records"]:
        if set(item) != {"code", "title", "category_id", "value", "status"}:
            raise ValueError(f"Некоректний набір полів запису: {item!r}")
    return data


def seed_database(data: dict) -> bool:
    """Заповнити порожню базу в одній транзакції.

    Повертає False, якщо в базі вже є дані.
    """
    with closing(get_connection()) as connection, connection:
        filled = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM categories)"
            " OR EXISTS (SELECT 1 FROM records)"
        ).fetchone()[0]
        if filled:
            return False
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(c["id"], c["name"]) for c in data["categories"]],
        )
        connection.executemany(
            "INSERT INTO records (code, title, category_id, value, status)"
            " VALUES (?, ?, ?, ?, ?)",
            [
                (
                    r["code"],
                    r["title"],
                    r["category_id"],
                    r["value"],
                    r["status"],
                )
                for r in data["records"]
            ],
        )
    return True


def main() -> int:
    try:
        data = load_seed()
        initialize_database()
        if seed_database(data):
            print(
                f"Базу заповнено: {len(data['categories'])} категорії, "
                f"{len(data['records'])} записів."
            )
        else:
            print("Дані вже заповнені, повторне заповнення не потрібне.")
    except (OSError, TypeError, ValueError, OverflowError) as error:
        print(f"Помилка початкових даних: {error}", file=sys.stderr)
        return 1
    except sqlite3.Error as error:
        print(
            f"Помилка бази даних, зміни скасовано: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
