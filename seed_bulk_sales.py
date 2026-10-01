"""
Допоміжний скрипт для лабораторної роботи №2.
Генерує великий обсяг тестових продажів (Sale + SaleItem) напряму в БД,
щоб /api/query6 (JOIN Sale -> SaleItem -> Product -> ProductCategory)
мав реальне навантаження під час k6-тестів.

Не змінює жодної існуючої логіки проєкту (app.py, models.py, queries.py) —
лише додає історичні дані для навантажувального тестування.

Запуск (з активованим venv, з кореня проєкту CURSOVA2):
    python3 seed_bulk_sales.py
"""
import random
from datetime import date, timedelta, datetime, time

from app import app, db
from models import Employee, Product

TARGET_SALES = 1500          # кількість продажів (Sale)
MAX_ITEMS_PER_SALE = 3        # до скількох товарів у кожному продажу
BATCH_SIZE = 200              # commit пачками для швидкості

def run():
    with app.app_context():
        employees = Employee.query.filter_by(is_deleted=False).all()
        products = Product.query.filter_by(is_deleted=False).all()

        if not employees or not products:
            print("Немає співробітників або товарів у БД. Спочатку запустіть init_db.py")
            return

        print(f"Знайдено {len(employees)} співробітників, {len(products)} товарів.")
        print(f"Генерую {TARGET_SALES} продажів...")

        today = date.today()
        created = 0

        for i in range(1, TARGET_SALES + 1):
            employee = random.choice(employees)

            sale_date = today - timedelta(days=random.randint(0, 90))
            sale_time = time(
                hour=random.randint(8, 20),
                minute=random.randint(0, 59),
                second=random.randint(0, 59)
            )

            from models import Sale, SaleItem
            new_sale = Sale(
                employee_id=employee.id,
                sale_date=sale_date,
                sale_time=sale_time,
                total_amount=0
            )
            db.session.add(new_sale)
            db.session.flush()  # отримати new_sale.id без коміту

            items_count = random.randint(1, MAX_ITEMS_PER_SALE)
            chosen_products = random.sample(products, k=min(items_count, len(products)))

            total = 0
            for product in chosen_products:
                quantity = random.randint(1, 5)
                unit_price = product.price
                total_price = float(unit_price) * quantity

                db.session.add(SaleItem(
                    sale_id=new_sale.id,
                    product_id=product.id,
                    quantity=quantity,
                    unit_price=unit_price,
                    total_price=total_price
                ))
                total += total_price

            new_sale.total_amount = total
            created += 1

            if created % BATCH_SIZE == 0:
                db.session.commit()
                print(f"  ...{created}/{TARGET_SALES} продажів створено")

        db.session.commit()
        print(f"Готово. Створено {created} продажів.")

        total_sale_items = db.session.query(SaleItem).count()
        print(f"Разом рядків у sale_items: {total_sale_items}")


if __name__ == "__main__":
    run()