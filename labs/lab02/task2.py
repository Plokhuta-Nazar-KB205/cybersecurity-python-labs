"""Завдання 2: CLI-утиліта аудиту HTTP-заголовків безпеки (варіант 9)."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_HEADERS_FILE = (
    Path(__file__).parent / "data" / "data_v09" / "headers.json"
)

# Рівень ALERT лежить між ERROR (40) і CRITICAL (50).
ALERT = 45
logging.addLevelName(ALERT, "ALERT")
logger = logging.getLogger("lab02.headers_audit")

BASE_SCORE = 100
PASS_THRESHOLD = 80
WARN_THRESHOLD = 60
LEAK_PENALTY = 10
HSTS_MIN_MAX_AGE = 31_536_000
# Літерні оцінки: (мінімальний бал, оцінка), від найвищої до найнижчої.
GRADES = ((95, "A+"), (90, "A"), (80, "B"), (60, "C"), (50, "D"))
LOWEST_GRADE = "F"

# Обов'язкові заголовки (ключ — у нижньому регістрі) і штраф за відсутність.
REQUIRED_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", 20),
    "content-security-policy": ("Content-Security-Policy", 20),
    "x-frame-options": ("X-Frame-Options", 10),
    "x-content-type-options": ("X-Content-Type-Options", 10),
}
# Заголовки, що можуть розкривати версію ПЗ.
LEAK_HEADERS = ("Server", "X-Powered-By")
# Продукт/версія з хоча б однією крапкою: Apache/2.4.41, PHP/7.4.3.
VERSION_PATTERN = re.compile(r"[A-Za-z][\w.\-]*/\d+(?:\.\d+)+")
MAX_AGE_PATTERN = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
WEAK_CSP_PATTERN = re.compile(
    r"'unsafe-(?:inline|eval)'|(?:^|[\s;])\*(?:\s|;|$)"
)
VALID_FRAME_OPTIONS = {"DENY", "SAMEORIGIN"}


@dataclass
class AuditResult:
    url: str
    score: int
    status: str
    grade: str = LOWEST_GRADE
    missing_headers: list[str] = field(default_factory=list)
    weak_headers: list[str] = field(default_factory=list)
    leaks: list[str] = field(default_factory=list)


def load_headers(path: Path) -> list[dict]:
    """Зчитує JSON зі списком {url, headers} і перевіряє його форму."""
    try:
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, list):
            raise TypeError("Очікується JSON-список об'єктів {url, headers}")
        for index, item in enumerate(data):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("url"), str)
                or not isinstance(item.get("headers"), dict)
            ):
                raise TypeError(f"Запис №{index} не містить url та headers")
    except FileNotFoundError as err:
        raise FileNotFoundError(
            f"Файл заголовків не знайдено: {path}"
        ) from err
    except ValueError as err:
        # json.JSONDecodeError теж є ValueError.
        raise ValueError(f"Некоректний формат JSON у файлі: {path}") from err
    except (TypeError, KeyError) as err:
        raise TypeError(
            f"Невідповідна структура даних у JSON: {path} ({err})"
        ) from err
    return data


def classify(score: int) -> str:
    if score >= PASS_THRESHOLD:
        return "PASS"
    if score >= WARN_THRESHOLD:
        return "WARN"
    return "FAIL"


def grade_for(score: int) -> str:
    for minimum, grade in GRADES:
        if score >= minimum:
            return grade
    return LOWEST_GRADE


def find_version_leaks(headers: dict[str, str]) -> list[str]:
    """Повертає рядки виду 'Server: Apache/2.4.41' для кожного витоку."""
    leaks = []
    for name in LEAK_HEADERS:
        value = headers.get(name.lower(), "")
        if VERSION_PATTERN.search(value):
            leaks.append(f"{name}: {value}")
    return leaks


def _weak_header_checks(headers: dict[str, str]) -> list[tuple[str, int]]:
    """Суворий режим: слабкі значення наявних заголовків (назва, штраф)."""
    weak = []
    hsts = headers.get("strict-transport-security")
    if hsts is not None:
        match = MAX_AGE_PATTERN.search(hsts)
        if match is None or int(match.group(1)) < HSTS_MIN_MAX_AGE:
            weak.append(("Strict-Transport-Security", 10))
    csp = headers.get("content-security-policy")
    if csp is not None and WEAK_CSP_PATTERN.search(csp):
        weak.append(("Content-Security-Policy", 10))
    frame = headers.get("x-frame-options")
    if frame is not None and frame.strip().upper() not in VALID_FRAME_OPTIONS:
        weak.append(("X-Frame-Options", 5))
    nosniff = headers.get("x-content-type-options")
    if nosniff is not None and nosniff.strip().lower() != "nosniff":
        weak.append(("X-Content-Type-Options", 5))
    return weak


def audit_site(
    url: str, raw_headers: dict, strict: bool = False
) -> AuditResult:
    # Імена HTTP-заголовків нечутливі до регістру.
    headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
    score = BASE_SCORE
    result = AuditResult(url=url, score=score, status="")

    for key, (name, penalty) in REQUIRED_HEADERS.items():
        if key not in headers:
            result.missing_headers.append(name)
            score -= penalty

    result.leaks = find_version_leaks(headers)
    score -= LEAK_PENALTY * len(result.leaks)

    if strict:
        for name, penalty in _weak_header_checks(headers):
            result.weak_headers.append(name)
            score -= penalty
        # Заголовок без версії теж розкриває технологію.
        for name in LEAK_HEADERS:
            value = headers.get(name.lower())
            if value and not VERSION_PATTERN.search(value):
                result.weak_headers.append(f"{name} (technology disclosed)")
                score -= 5

    result.score = max(score, 0)
    result.status = classify(result.score)
    result.grade = grade_for(result.score)
    return result


def _log_result(result: AuditResult) -> None:
    for name in result.missing_headers:
        logger.warning("%s: відсутній заголовок %s", result.url, name)
    for name in result.weak_headers:
        logger.warning("%s: слабке значення: %s", result.url, name)
    for leak in result.leaks:
        logger.log(ALERT, "%s: витік версії ПЗ (%s)", result.url, leak)
    message = "%s: score=%d status=%s"
    args = (result.url, result.score, result.status)
    if result.status == "FAIL":
        logger.log(ALERT, message, *args)
    elif result.status == "WARN":
        logger.warning(message, *args)
    else:
        logger.info(message, *args)


def print_table(results: list[AuditResult]) -> None:
    """Виводить таблицю результатів аудиту у стандартний вивід."""
    rows = [
        (
            result.url,
            f"{result.score}/{BASE_SCORE} ({result.grade})",
            result.status,
            ", ".join(result.missing_headers) or "None",
        )
        for result in results
    ]
    titles = (
        "Target Resource",
        "Security Score",
        "Status",
        "Missing Security Headers",
    )
    widths = [
        max(len(row[i]) for row in [titles, *rows]) for i in range(len(titles))
    ]
    template = "  ".join(f"{{:<{width}}}" for width in widths)
    print()
    print(template.format(*titles).rstrip())
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row in rows:
        print(template.format(*row).rstrip())


def print_leaks(results: list[AuditResult]) -> None:
    """Виводить секцію витоків версій ПЗ (Server / X-Powered-By)."""
    print("\n=== Server Software Leak Alerts ===")
    found = False
    for result in results:
        for leak in result.leaks:
            name, _, value = leak.partition(": ")
            kind = "version" if name == "Server" else "tech stack"
            print(f"[LEAK] {result.url} leaks {kind} in '{name}': {value}")
            found = True
    if not found:
        print("No software version leaks detected.")


def export_csv(results: list[AuditResult], path: Path) -> bool:
    """Записує CSV-звіт; повертає False, якщо запис не вдався."""
    columns = [
        "url",
        "score",
        "status",
        "grade",
        "missing_headers",
        "weak_headers",
        "leaks",
    ]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            for result in results:
                row = asdict(result)
                for key in ("missing_headers", "weak_headers", "leaks"):
                    row[key] = "; ".join(row[key])
                writer.writerow(row)
    except OSError as err:
        logger.error("Помилка запису у файл %s: %s", path, err)
        return False
    return True


def export_json(
    results: list[AuditResult],
    path: Path,
    strict: bool,
) -> bool:
    """Записує JSON-звіт; повертає False, якщо запис не вдався."""
    report = {
        "strict": strict,
        "total": len(results),
        "results": [asdict(result) for result in results],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)
            file.write("\n")
    except OSError as err:
        logger.error("Помилка запису у файл %s: %s", path, err)
        return False
    return True


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Додає аргументи утиліти (використовується й підкомандою analyze)."""
    parser.add_argument(
        "--headers-file",
        type=Path,
        default=DEFAULT_HEADERS_FILE,
        help="JSON-файл із заголовками (за замовчуванням: %(default)s)",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        help="шлях для CSV-звіту",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="шлях для JSON-звіту",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="суворіше оцінювання: перевірка значень заголовків",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="рівень логування (за замовчуванням: %(default)s)",
    )


def run(args: argparse.Namespace) -> int:
    """Виконує аудит за розібраними аргументами; повертає код виходу."""
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="[%(levelname)s] %(message)s",
        force=True,
    )
    logger.info("Auditing HTTP response headers from %s...", args.headers_file)
    try:
        sites = load_headers(args.headers_file)
    except (OSError, ValueError, TypeError) as error:
        # json.JSONDecodeError теж є ValueError.
        logger.error("Не вдалося прочитати %s: %s", args.headers_file, error)
        return 1

    results = [
        audit_site(site["url"], site["headers"], args.strict) for site in sites
    ]
    for result in results:
        _log_result(result)

    print_table(results)
    print_leaks(results)

    counts = {status: 0 for status in ("PASS", "WARN", "FAIL")}
    for result in results:
        counts[result.status] += 1
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(f"\nПеревірено сайтів: {len(results)} ({summary})")

    if args.output_csv:
        if not export_csv(results, args.output_csv):
            return 1
        logger.info("Header audit report generated at %s", args.output_csv)
    if args.output_json:
        if not export_json(results, args.output_json, args.strict):
            return 1
        logger.info("Header audit report generated at %s", args.output_json)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Аудит HTTP-заголовків безпеки (варіант 9)",
    )
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
