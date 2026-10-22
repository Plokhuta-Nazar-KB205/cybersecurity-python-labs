"""FastAPI-застосунок: облік часу опрацювання повідомлень."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03 import config
from labs.lab03.database import initialize_database
from labs.lab03.repository import RepositoryError
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Сервіс обліку тривалості перевірки повідомлень про події безпеки. "
    "Категорія визначає джерело повідомлення (siem, helpdesk, monitoring), "
    "value — тривалість у хвилинах (float, не менше 0), "
    "status — стан перевірки вимірювання. "
    f"Одиниця вимірювання: {config.UNIT}. Поріг: {config.THRESHOLD}."
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску, не чіпаючи дані."""
    initialize_database()
    yield


app = FastAPI(title=config.TITLE, description=DESCRIPTION, lifespan=lifespan)


@app.exception_handler(RequestValidationError)
def handle_validation_error(request: Request, error: RequestValidationError):
    """422 без вхідних значень: NaN/Infinity не серіалізуються в JSON."""
    errors = [
        {key: item[key] for key in ("type", "loc", "msg")}
        for item in error.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(RepositoryError)
def handle_repository_error(request: Request, error: RepositoryError):
    """Технічні деталі — у журнал, клієнту — загальне повідомлення."""
    logger.error(
        "Помилка бази даних: %s %s (%r)",
        request.url.path,
        error,
        error.__cause__,
    )
    return JSONResponse(
        status_code=500, content={"detail": "Внутрішня помилка сервера"}
    )


@app.get("/ping", summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/student", summary="Дані студента")
def student() -> dict[str, str | int]:
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }


app.include_router(categories.router)
app.include_router(records.router)
