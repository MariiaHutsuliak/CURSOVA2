"""
Лабораторна робота №3, Завдання 1 — захисні (characterization) тести для
маршруту редагування продажу `edit_sale` (app.py, POST /sales/edit/<id>).

Мета: зафіксувати ПОТОЧНУ бізнес-поведінку функції ДО рефакторингу, щоб після
зміни структури коду довести, що поведінка не змінилась.

Тести створюють власні ізольовані дані (відділи, співробітника, товари, продаж)
з унікальними назвами та повністю прибирають їх після себе, тому реальні
дані БД не змінюються.

Сценарії:
 1. GET — форма редагування відкривається.
 2. Основний: зміна кількостей оновлює залишки, позиції та суму.
 3. Основний: заміна товару повертає старий і списує новий.
 4. Граничний: кількість рівно дорівнює доступному залишку — дозволено.
 5. Граничний: кількість на 1 більша за залишок — відхилено, залишки не змінились.
 6. Порожній продаж (усі кількості порожні/0/текст) — відхилено.
 7. Некоректні/нульові рядки пропускаються, коректні зберігаються.
 8. Товар з іншого відділу — відхилено, відкат залишків.
"""
import uuid
from decimal import Decimal

import pytest

from app import app as flask_app
from models import (
    db, Department, ProductCategory, Employee, Product, Sale, SaleItem,
)


@pytest.fixture
def sale_env(client):
    """
    Ізольоване середовище: відділ A (співробітник + 2 товари), відділ B (1 товар),
    початковий продаж: товар1 x2 (ціна 100.00). Початкові залишки:
    товар1 = 10 (після продажу), товар2 = 5, чужий товар = 7.
    """
    tag = uuid.uuid4().hex[:8]
    with flask_app.app_context():
        dept_a = Department(name=f"T-A-{tag}")
        dept_b = Department(name=f"T-B-{tag}")
        category = ProductCategory(name=f"T-CAT-{tag}")
        db.session.add_all([dept_a, dept_b, category])
        db.session.flush()

        employee = Employee(
            first_name="Тест", last_name=f"Продавець{tag}", position="Продавець",
            department_id=dept_a.id,
        )
        db.session.add(employee)

        def make_product(name, price, stock, dept):
            return Product(
                name=f"{name}-{tag}", price=Decimal(price), stock_quantity=stock,
                category_id=category.id, department_id=dept.id,
            )

        p1 = make_product("Книга1", "100.00", 10, dept_a)
        p2 = make_product("Книга2", "50.00", 5, dept_a)
        foreign = make_product("Чужа", "30.00", 7, dept_b)
        db.session.add_all([p1, p2, foreign])
        db.session.flush()

        sale = Sale(employee_id=employee.id, total_amount=Decimal("200.00"))
        db.session.add(sale)
        db.session.flush()
        db.session.add(SaleItem(
            sale_id=sale.id, product_id=p1.id, quantity=2,
            unit_price=p1.price, total_price=Decimal("200.00"),
        ))
        db.session.commit()

        env = {
            "sale_id": sale.id, "p1": p1.id, "p2": p2.id, "foreign": foreign.id,
            "dept_ids": [dept_a.id, dept_b.id], "category_id": category.id,
            "employee_id": employee.id,
        }

    yield client, env

    with flask_app.app_context():
        db.session.rollback()
        SaleItem.query.filter_by(sale_id=env["sale_id"]).delete()
        Sale.query.filter_by(id=env["sale_id"]).delete()
        Product.query.filter(
            Product.id.in_([env["p1"], env["p2"], env["foreign"]])
        ).delete(synchronize_session=False)
        Employee.query.filter_by(id=env["employee_id"]).delete()
        ProductCategory.query.filter_by(id=env["category_id"]).delete()
        Department.query.filter(Department.id.in_(env["dept_ids"])).delete(
            synchronize_session=False
        )
        db.session.commit()


def _state(env):
    """Знімок стану: залишки, позиції продажу та загальна сума."""
    with flask_app.app_context():
        stock = {
            name: db.session.get(Product, env[name]).stock_quantity
            for name in ("p1", "p2", "foreign")
        }
        items = {
            i.product_id: (i.quantity, Decimal(i.unit_price), Decimal(i.total_price))
            for i in SaleItem.query.filter_by(sale_id=env["sale_id"]).all()
        }
        total = Decimal(db.session.get(Sale, env["sale_id"]).total_amount)
    return stock, items, total


def _post(client, env, quantities):
    data = {f"quantity_{env[name]}": value for name, value in quantities.items()}
    return client.post(f"/sales/edit/{env['sale_id']}", data=data)


def test_get_edit_form_opens(sale_env):
    client, env = sale_env
    response = client.get(f"/sales/edit/{env['sale_id']}")
    assert response.status_code == 200


def test_edit_updates_quantities_stock_items_and_total(sale_env):
    client, env = sale_env

    response = _post(client, env, {"p1": "3", "p2": "2"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/sales")
    stock, items, total = _state(env)
    # старі 2 повернуті (10+2=12), потім списано 3 -> 9; товар2: 5-2=3
    assert stock == {"p1": 9, "p2": 3, "foreign": 7}
    assert items == {
        env["p1"]: (3, Decimal("100.00"), Decimal("300.00")),
        env["p2"]: (2, Decimal("50.00"), Decimal("100.00")),
    }
    assert total == Decimal("400.00")


def test_edit_replaces_product_returns_old_and_writes_off_new(sale_env):
    client, env = sale_env

    response = _post(client, env, {"p2": "4"})

    assert response.status_code == 302
    stock, items, total = _state(env)
    assert stock == {"p1": 12, "p2": 1, "foreign": 7}
    assert items == {env["p2"]: (4, Decimal("50.00"), Decimal("200.00"))}
    assert total == Decimal("200.00")


def test_edit_boundary_quantity_equal_to_available_stock_is_allowed(sale_env):
    client, env = sale_env

    # Доступно товару1 після повернення старих 2 шт.: 10 + 2 = 12
    response = _post(client, env, {"p1": "12"})

    assert response.status_code == 302
    stock, items, total = _state(env)
    assert stock["p1"] == 0
    assert items[env["p1"]][0] == 12
    assert total == Decimal("1200.00")


def test_edit_boundary_quantity_above_stock_is_rejected_without_changes(sale_env):
    client, env = sale_env
    before = _state(env)

    response = _post(client, env, {"p1": "13"})

    assert response.status_code == 302
    assert f"/sales/edit/{env['sale_id']}" in response.headers["Location"]
    assert _state(env) == before


@pytest.mark.parametrize("raw", [{"p1": ""}, {"p1": "0"}, {"p1": "-3"}, {"p1": "abc"}])
def test_edit_empty_sale_is_rejected_without_changes(sale_env, raw):
    client, env = sale_env
    before = _state(env)

    response = _post(client, env, raw)

    assert response.status_code == 302
    assert f"/sales/edit/{env['sale_id']}" in response.headers["Location"]
    assert _state(env) == before


def test_edit_skips_invalid_rows_and_keeps_valid_ones(sale_env):
    client, env = sale_env

    response = _post(client, env, {"p1": "abc", "p2": "1"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/sales")
    stock, items, total = _state(env)
    assert stock == {"p1": 12, "p2": 4, "foreign": 7}
    assert items == {env["p2"]: (1, Decimal("50.00"), Decimal("50.00"))}
    assert total == Decimal("50.00")


def test_edit_product_from_other_department_is_rejected_with_rollback(sale_env):
    client, env = sale_env
    before = _state(env)

    response = _post(client, env, {"p1": "1", "foreign": "1"})

    assert response.status_code == 302
    assert f"/sales/edit/{env['sale_id']}" in response.headers["Location"]
    assert _state(env) == before
