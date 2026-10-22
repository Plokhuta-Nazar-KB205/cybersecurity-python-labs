"""Маршрути категорій."""

from fastapi import APIRouter, HTTPException, Path

from labs.lab03 import repository
from labs.lab03.repository import (
    DuplicateError,
    FKConstraintError,
    NotFoundError,
)
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
    description="Повертає всі категорії за зростанням id.",
)
def list_categories() -> list[dict]:
    return repository.get_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate) -> dict:
    try:
        return repository.create_category(category.name)
    except DuplicateError:
        raise HTTPException(
            status_code=409, detail="Категорія з такою назвою вже існує"
        ) from None


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: int = Path(gt=0, description="Ідентифікатор категорії"),
) -> None:
    try:
        repository.delete_category(category_id)
    except NotFoundError:
        raise HTTPException(
            status_code=404, detail="Категорію не знайдено"
        ) from None
    except FKConstraintError:
        raise HTTPException(
            status_code=409,
            detail="Неможливо видалити категорію, яка містить записи",
        ) from None
