"""Маршрути записів (вимірювань часу опрацювання)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Body, HTTPException, Path, Query

from labs.lab03 import repository
from labs.lab03.repository import CATEGORY, DuplicateError, NotFoundError
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["records"])

DUPLICATE_CODE = "Запис із таким кодом вже існує"
RECORD_NOT_FOUND = "Запис не знайдено"
CATEGORY_NOT_FOUND = "Вказана категорія не існує"


def _not_found(error: NotFoundError) -> HTTPException:
    """404 з повідомленням про відсутню категорію або запис."""
    detail = (
        CATEGORY_NOT_FOUND if error.resource == CATEGORY else RECORD_NOT_FOUND
    )
    return HTTPException(status_code=404, detail=detail)


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами",
    description=(
        "Фільтри поєднуються через AND, результат відсортований за id. "
        "Неіснуюча категорія дає порожній список."
    ),
)
def list_records(
    category_id: int | None = Query(
        default=None, gt=0, description="Лише записи категорії"
    ),
    status: Literal["new", "in_progress", "done"] | None = Query(
        default=None, description="Лише записи з цим статусом"
    ),
    min_value: float | None = Query(
        default=None, ge=0, description="Мінімальна тривалість, хвилини"
    ),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=120,
        description="Підрядок у title з урахуванням регістру",
    ),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return repository.get_records(
        category_id=category_id,
        status=status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    description="Усі записи зберігаються атомарно в одній транзакції.",
    responses={
        404: {"description": "Одна з вказаних категорій не існує"},
        409: {"description": "Дублювання коду в пакеті або в базі даних"},
    },
)
def bulk_create_records(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    try:
        return repository.bulk_create_records(records)
    except NotFoundError:
        raise HTTPException(
            status_code=404, detail="Одна з вказаних категорій не існує"
        ) from None
    except DuplicateError:
        raise HTTPException(
            status_code=409,
            detail="Дублювання коду в пакеті або в базі даних",
        ) from None


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Один запис",
    responses={404: {"description": RECORD_NOT_FOUND}},
)
def get_record(
    record_id: int = Path(gt=0, description="Ідентифікатор запису"),
) -> dict:
    record = repository.get_record_by_id(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=RECORD_NOT_FOUND)
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={
        404: {"description": CATEGORY_NOT_FOUND},
        409: {"description": DUPLICATE_CODE},
    },
)
def create_record(record: RecordCreate) -> dict:
    try:
        return repository.create_record(record)
    except NotFoundError as error:
        raise _not_found(error) from None
    except DuplicateError:
        raise HTTPException(status_code=409, detail=DUPLICATE_CODE) from None


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна запису",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": DUPLICATE_CODE},
    },
)
def replace_record(
    record: RecordReplace,
    record_id: int = Path(gt=0, description="Ідентифікатор запису"),
) -> dict:
    try:
        return repository.update_record(record_id, record)
    except NotFoundError as error:
        raise _not_found(error) from None
    except DuplicateError:
        raise HTTPException(status_code=409, detail=DUPLICATE_CODE) from None


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    responses={404: {"description": RECORD_NOT_FOUND}},
)
def delete_record(
    record_id: int = Path(gt=0, description="Ідентифікатор запису"),
) -> None:
    try:
        repository.delete_record(record_id)
    except NotFoundError as error:
        raise _not_found(error) from None
