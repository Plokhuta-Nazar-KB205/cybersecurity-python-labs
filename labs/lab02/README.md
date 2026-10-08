# Лабораторна робота № 2

**Тема:** Розробка консольних утиліт для задач кібербезпеки  
**Дисципліна:** Програмування скриптовими мовами  
**Студент:** Плохута Назар Сергійович, група КБ-205  
**Варіант:** 9 — Аудитор безпеки HTTP-заголовків відповідей  
**Мова:** Python 3.10+, лінтер і форматер — Ruff

## Встановлення залежностей

З кореня репозиторію, в активованому віртуальному середовищі з ЛР №1:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Структура

```text
labs/lab02/
├── __init__.py
├── main.py                 # точка входу: команди demo та analyze
├── task1.py                # ООП-модель: User, Admin, Session, AuditLog, UserAccount
├── task2.py                # CLI-аудитор HTTP-заголовків
├── README.md
└── data/
    └── data_v09/           # каталог варіанта з архіву lab2_data.zip
        └── headers.json    # вхід завдання 2
```

Єдиний вхідний файл утиліти — `labs/lab02/data/data_v09/headers.json`
(назва й вкладеність збережені як в архіві). Це JSON-список об'єктів
`{"url": ..., "headers": {...}}`. CSV/JSON-звіти (`headers_audit.*`)
створюються при запуску й додані до `.gitignore`.

## Запуск

З кореня репозиторію:

```bash
python -m labs.lab02.main demo
python -m labs.lab02.main analyze \
    --headers-file labs/lab02/data/data_v09/headers.json \
    --output-csv labs/lab02/data/headers_audit.csv
python -m labs.lab02.main analyze --strict --log-level WARNING
```

Утиліту із завдання 2 можна запускати й окремо:
`python -m labs.lab02.task2 --help`.

Перевірка стилю:

```bash
ruff check .
ruff format --check .
```

## Завдання 1. ООП-модель (`task1.py`)

- **User** — `username`, `role`, `active`, email-властивість. Email
  перевіряється регулярним виразом (локальна частина: латинська літера
  першою, усього 3–64 символи з латинських літер, цифр і `_`; домен із
  принаймні однією крапкою), інакше `ValueError`. Пароль зберігається лише
  як сіль (`os.urandom(16)`) і хеш `pbkdf2_hmac("sha256", ..., 100000)`
  у приватних полях; `check_password` порівнює через `hmac.compare_digest`.
- **Admin(User)** — набір `permissions` (за замовчуванням `None` →
  порожня `set`, тому змінюваного дефолту немає), методи
  `grant_permission`, `revoke_permission`, `has_permission`; `__str__`
  розширює батьківський через `super()`.
- **Session** — `ip`, `login_time`, `last_activity` в UTC; `touch()`;
  `is_active(timeout_sec)` кидає `ValueError`, якщо `timeout_sec <= 0`.
- **AuditEntry** (`dataclass`) і **AuditLog** — події лише
  `login_success`, `login_failure`, `logout`; інша подія — `ValueError`.
  Пароль у журнал не передається взагалі.
- **UserAccount** — композиція `User` + `Session | None` + `AuditLog`,
  `SESSION_TIMEOUT_SEC = 900`.

Рішення, які не випливають із завдання напряму:

- Сеанс створюється тільки при успішному вході; невдала спроба
  (невірний пароль, чужий логін, неактивний акаунт) пишеться як
  `login_failure` і не змінює поточний сеанс.
- `is_authenticated()` для прострочених сеансів повертає `False` і **не**
  оновлює `last_activity`; успішна перевірка, навпаки, викликає `touch()`
  (ковзне вікно неактивності).
- `logout()` без сеансу нічого не робить і не пише в журнал.
- `account[...]`: ключі `user`, `session`, `audit_log`. Невідомий ключ —
  `KeyError`, не-рядок — `TypeError`, значення неправильного типу в
  `__setitem__` — `TypeError`. Будь-який ключ, що містить `password`
  (зокрема `__password_hash`, `__password_salt`), дає `PermissionError`.

## Завдання 2. Аудит HTTP-заголовків (`task2.py`)

Вхід — JSON-список `{"url": ..., "headers": {...}}`. Імена заголовків
порівнюються без урахування регістру.

**Вивід.** Журнал (`logging`) іде у stderr у форматі `[LEVEL] повідомлення`.
У stdout друкуються таблиця результатів
(`Target Resource | Security Score | Status | Missing Security Headers`),
секція `=== Server Software Leak Alerts ===` з рядками `[LEAK] ...` і
підсумок. Приклад (тестові дані, без `--strict`):

```text
Target Resource                   Security Score  Status  Missing Security Headers
------------------------------------------------------------------------------------------------------------------------
https://secure.example.invalid/   100/100 (A+)    PASS    None
https://legacy.example.invalid/   30/100 (F)      FAIL    Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options
https://api.example.invalid/      80/100 (B)      PASS    X-Frame-Options

=== Server Software Leak Alerts ===
[LEAK] https://legacy.example.invalid/ leaks version in 'Server': Apache/2.4.49
[LEAK] https://legacy.example.invalid/ leaks tech stack in 'X-Powered-By': PHP/7.4.3
```

**Бали** (база 100):

| Порушення | Штраф |
|---|---|
| Немає `Strict-Transport-Security` | −20 |
| Немає `Content-Security-Policy` | −20 |
| Немає `X-Frame-Options` | −10 |
| Немає `X-Content-Type-Options` | −10 |
| Версія ПЗ в `Server` або `X-Powered-By` (кожен заголовок) | −10 |

Витік версії — це збіг з `[A-Za-z][\w.\-]*/\d+(\.\d+)+`
(`Apache/2.4.41`, `PHP/7.4.3`); `Express` чи `web-gateway` без версії
витоком не вважаються. Мінімальний бал — 0.

**Класифікація:** `PASS` ≥ 80, `WARN` 60–79, `FAIL` < 60.

**Літерна оцінка:** `A+` ≥ 95, `A` ≥ 90, `B` ≥ 80, `C` ≥ 60, `D` ≥ 50,
інакше `F`. Вона показується в таблиці та записується в стовпець `grade`
CSV/JSON-звіту.

**`--strict`** додатково штрафує:

- HSTS без `max-age` або з `max-age` < 31536000 — −10;
- CSP з `'unsafe-inline'`, `'unsafe-eval'` або `*` — −10;
- `X-Frame-Options` не `DENY`/`SAMEORIGIN` — −5;
- `X-Content-Type-Options` не `nosniff` — −5;
- `Server`/`X-Powered-By` без версії, але з назвою технології — −5.

**Логування:** модуль `logging`; `INFO` — сайт пройшов, `WARNING` —
відсутній або слабкий заголовок, оцінка `WARN`; `ALERT` (власний рівень 45,
між `ERROR` і `CRITICAL`) — витік версії та оцінка `FAIL`. Тому
`--log-level ERROR` показує лише `ALERT`.

**Аргументи:**

| Аргумент | Опис |
|---|---|
| `--headers-file` | вхідний JSON (за замовчуванням `labs/lab02/data/data_v09/headers.json`) |
| `--output-csv` | зберегти звіт у CSV (стовпці: `url`, `score`, `status`, `grade`, `missing_headers`, `weak_headers`, `leaks`) |
| `--output-json` | зберегти звіт у JSON (можна разом з CSV) |
| `--strict` | суворіше оцінювання |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## Поведінка при помилках

Помилки не призводять до traceback: вони пишуться в журнал рівнем `ERROR`,
утиліта завершується з кодом `1`.

| Ситуація | Що відбувається |
|---|---|
| Вхідного файлу немає або він недоступний | `ERROR Не вдалося прочитати <файл>: ...`, код `1` |
| Файл не є коректним JSON | `ERROR` з позицією помилки, код `1` |
| JSON не є списком або запис без `url`/`headers` | `ERROR Запис №N не містить url та headers`, код `1` |
| Не вдалося записати CSV/JSON-звіт | `ERROR Не вдалося записати звіт: ...`, код `1` |
| Неправильний аргумент (`--log-level`, невідомий прапорець) | повідомлення `argparse`, код `2` |

Каталог для звіту створюється автоматично. Код `0` — аудит виконано, навіть
якщо знайдено сайти зі статусом `FAIL`.

## Результат на тестових даних

| URL | Бал | Оцінка | Статус | Бал (`--strict`) | Оцінка (`--strict`) | Статус (`--strict`) |
|---|---|---|---|---|---|---|
| secure.example.invalid | 100 | A+ | PASS | 95 | A+ | PASS |
| legacy.example.invalid | 30 | F | FAIL | 30 | F | FAIL |
| api.example.invalid | 80 | B | PASS | 70 | C | WARN |
| portal.example.invalid | 100 | A+ | PASS | 95 | A+ | PASS |
| minimal.example.invalid | 30 | F | FAIL | 30 | F | FAIL |

## Перевірка

З кореня репозиторію `ruff check .` і `ruff format --check .` проходять без
зауважень. Команди `demo` та `analyze` виконано вручну, результати
наведені вище.
