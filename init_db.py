from app import app, db
from models import *
from datetime import datetime, date, time, timedelta
from decimal import Decimal

def init_database():
    with app.app_context():

        db.create_all()

        admin_user = User(
            username="admin",
            email="admin@bookstore.ua",
            role="administrator",
            is_active=True
        )
        admin_user.set_password("admin123")
        db.session.add(admin_user)
        db.session.commit()

        print("Створено адміністратора системи:")
        print("Логін: admin")
        print("Пароль: admin123")
        print("Email: admin@bookstore.ua")
        print("Роль: administrator")
        print("-" * 50)

        operator_user = User(
            username="operator",
            email="operator@bookstore.ua",
            role="operator",
            is_active=True
        )
        operator_user.set_password("operator123")
        db.session.add(operator_user)
        db.session.commit()

        print("Створено оператора системи:")
        print("Логін: operator")
        print("Пароль: operator123")
        print("Email: operator@bookstore.ua")
        print("Роль: operator")
        print("-" * 50)

        auth_user = User(
            username="user",
            email="user@bookstore.ua",
            role="authorized_user",
            is_active=True
        )
        auth_user.set_password("user123")
        db.session.add(auth_user)
        db.session.commit()

        print("Створено авторизованого користувача:")
        print("Логін: user")
        print("Пароль: user123")
        print("Email: user@bookstore.ua")
        print("Роль: authorized_user")
        print("-" * 50)

        departments = [
            Department(name="Комп'ютерна література", description="Книги з програмування та IT"),
            Department(name="Детективи", description="Детективні романи та трилери"),
            Department(name="Дитяча книга", description="Книги для дітей різного віку"),
            Department(name="Медицина", description="Медична література"),
            Department(name="Періодика", description="Газети та журнали"),
            Department(name="Настільні ігри", description="Настільні ігри та головоломки")
        ]
        
        for dept in departments:
            db.session.add(dept)
        db.session.commit()

        categories = [
            ProductCategory(name="Комп'ютерна література", description="Книги з програмування, веб-розробки, ІТ"),
            ProductCategory(name="Детективи", description="Детективні романи, трилери, містика"),
            ProductCategory(name="Дитяча література", description="Книги для дітей та підлітків"),
            ProductCategory(name="Медична література", description="Медичні підручники та довідники"),
            ProductCategory(name="Газети", description="Щоденні та тижневі газети"),
            ProductCategory(name="Журнали", description="Різноманітні журнали"),
            ProductCategory(name="Календарі", description="Настінні та настільні календарі"),
            ProductCategory(name="Настільні ігри", description="Ігри для всієї родини")
        ]
        
        for cat in categories:
            db.session.add(cat)
        db.session.commit()

        employees = [
            Employee(first_name="Олена", last_name="Іваненко", position="керівник відділу", 
                    phone="+380501234567", email="olena.ivanenko@bookstore.ua", 
                    department_id=1, hire_date=date(2020, 1, 15)),
            Employee(first_name="Петро", last_name="Петренко", position="продавець-консультант", 
                    phone="+380502345678", email="petro.petrenko@bookstore.ua", 
                    department_id=1, hire_date=date(2021, 3, 10)),
            Employee(first_name="Марія", last_name="Сидоренко", position="касир", 
                    phone="+380503456789", email="maria.sydorenko@bookstore.ua", 
                    department_id=2, hire_date=date(2021, 6, 1)),
            Employee(first_name="Андрій", last_name="Коваленко", position="керівник відділу", 
                    phone="+380504567890", email="andriy.kovalenko@bookstore.ua", 
                    department_id=2, hire_date=date(2019, 9, 20)),
            Employee(first_name="Тетяна", last_name="Мельник", position="продавець-консультант", 
                    phone="+380505678901", email="tetyana.melnyk@bookstore.ua", 
                    department_id=3, hire_date=date(2022, 1, 12), is_on_vacation=True),
            Employee(first_name="Василь", last_name="Шевченко", position="касир", 
                    phone="+380506789012", email="vasyl.shevchenko@bookstore.ua", 
                    department_id=4, hire_date=date(2020, 11, 5))
        ]
        
        for emp in employees:
            db.session.add(emp)
        db.session.commit()

        suppliers = [
            Supplier(name="Видавництво 'Техніка'", contact_person="Іван Технічний", 
                    phone="+380441234567", email="info@technika.ua", 
                    address="м. Київ, вул. Технічна, 15"),
            Supplier(name="Детектив-Прес", contact_person="Олександр Детективний", 
                    phone="+380442345678", email="sales@detective-press.ua", 
                    address="м. Харків, вул. Детективна, 22"),
            Supplier(name="Дитяче видавництво 'Казка'", contact_person="Світлана Казкова", 
                    phone="+380443456789", email="orders@kazka.ua", 
                    address="м. Львів, вул. Казкова, 8"),
            Supplier(name="Медичне видавництво 'Здоров'я'", contact_person="Микола Медичний", 
                    phone="+380444567890", email="med@zdorovya.ua", 
                    address="м. Дніпро, вул. Медична, 30"),
            Supplier(name="Преса України", contact_person="Галина Пресова", 
                    phone="+380445678901", email="distribution@press.ua", 
                    address="м. Одеса, вул. Пресова, 12")
        ]
        
        for supplier in suppliers:
            db.session.add(supplier)
        db.session.commit()

        contracts = [
            Contract(contract_number="DOG-2023-001", supplier_id=1, 
                    start_date=date(2023, 1, 1), end_date=date(2023, 12, 31)),
            Contract(contract_number="DOG-2023-002", supplier_id=2, 
                    start_date=date(2023, 2, 1), end_date=date(2024, 1, 31)),
            Contract(contract_number="DOG-2023-003", supplier_id=3, 
                    start_date=date(2023, 3, 1), end_date=date(2023, 12, 31)),
            Contract(contract_number="DOG-2023-004", supplier_id=4, 
                    start_date=date(2023, 1, 15), end_date=date(2024, 1, 15)),
            Contract(contract_number="DOG-2025-005", supplier_id=5,
                    start_date=date(2025, 1, 1), end_date=date(2025, 12, 31))
        ]
        
        for contract in contracts:
            db.session.add(contract)
        db.session.commit()

        products = [
            Product(name="Python для початківців", author="Іван Програміст", 
                   isbn="978-966-1234-56-7", publisher="Техніка", 
                   publication_date=date(2023, 1, 15), price=Decimal("450.00"), 
                   stock_quantity=25, category_id=1, department_id=1),
            Product(name="JavaScript. Повний курс", author="Петро Веб-розробник", 
                   isbn="978-966-2345-67-8", publisher="Техніка", 
                   publication_date=date(2023, 2, 20), price=Decimal("520.00"), 
                   stock_quantity=18, category_id=1, department_id=1),

            Product(name="Вбивство в орієнт-експресі", author="Агата Крісті", 
                   isbn="978-966-3456-78-9", publisher="Детектив-Прес", 
                   publication_date=date(2022, 11, 10), price=Decimal("280.00"), 
                   stock_quantity=35, category_id=2, department_id=2),
            Product(name="Шерлок Холмс. Повне зібрання", author="Артур Конан Дойл", 
                   isbn="978-966-4567-89-0", publisher="Детектив-Прес", 
                   publication_date=date(2023, 1, 5), price=Decimal("650.00"), 
                   stock_quantity=12, category_id=2, department_id=2),

            Product(name="Гаррі Поттер і філософський камінь", author="Дж.К. Роулінг", 
                   isbn="978-966-5678-90-1", publisher="Казка", 
                   publication_date=date(2022, 12, 1), price=Decimal("380.00"), 
                   stock_quantity=28, category_id=3, department_id=3),

            Product(name="Анатомія людини", author="Проф. Медичний", 
                   isbn="978-966-6789-01-2", publisher="Здоров'я", 
                   publication_date=date(2023, 3, 1), price=Decimal("850.00"), 
                   stock_quantity=8, category_id=4, department_id=4),

            Product(name="Українська правда (щоденна)", publisher="Преса України", 
                   publication_date=date.today(), price=Decimal("15.00"), 
                   stock_quantity=100, category_id=5, department_id=5),

            Product(name="Комп'ютерний світ", publisher="Преса України", 
                   publication_date=date(2023, 9, 1), price=Decimal("45.00"), 
                   stock_quantity=50, category_id=6, department_id=5),

            Product(name="Календар настінний 2024", publisher="Преса України", 
                   publication_date=date(2023, 10, 1), price=Decimal("120.00"), 
                   stock_quantity=75, category_id=7, department_id=5),

            Product(name="Монополія", publisher="Ігри для всіх", 
                   publication_date=date(2023, 5, 1), price=Decimal("890.00"), 
                   stock_quantity=15, category_id=8, department_id=6)
        ]
        
        for product in products:
            db.session.add(product)
        db.session.commit()

        contract_products = [
            ContractProduct(contract_id=1, product_id=1, quantity_per_delivery=10, purchase_price=Decimal("350.00")),
            ContractProduct(contract_id=1, product_id=2, quantity_per_delivery=8, purchase_price=Decimal("420.00")),
            ContractProduct(contract_id=2, product_id=3, quantity_per_delivery=15, purchase_price=Decimal("220.00")),
            ContractProduct(contract_id=2, product_id=4, quantity_per_delivery=5, purchase_price=Decimal("550.00")),
            ContractProduct(contract_id=3, product_id=5, quantity_per_delivery=12, purchase_price=Decimal("300.00")),
            ContractProduct(contract_id=4, product_id=6, quantity_per_delivery=3, purchase_price=Decimal("700.00")),
            ContractProduct(contract_id=5, product_id=7, quantity_per_delivery=50, purchase_price=Decimal("12.00")),
            ContractProduct(contract_id=5, product_id=9, quantity_per_delivery=25, purchase_price=Decimal("95.00"))
        ]
        
        for cp in contract_products:
            db.session.add(cp)
        db.session.commit()

        today = date.today()
        for i in range(7):
            work_date = today + timedelta(days=i)
            schedules = [
                WorkSchedule(employee_id=1, department_id=1, work_date=work_date, 
                           shift_start=time(9, 0), shift_end=time(18, 0)),
                WorkSchedule(employee_id=2, department_id=1, work_date=work_date, 
                           shift_start=time(10, 0), shift_end=time(19, 0)),
                WorkSchedule(employee_id=3, department_id=2, work_date=work_date, 
                           shift_start=time(9, 0), shift_end=time(18, 0)),
                WorkSchedule(employee_id=4, department_id=2, work_date=work_date, 
                           shift_start=time(8, 0), shift_end=time(17, 0)),
                WorkSchedule(employee_id=6, department_id=4, work_date=work_date, 
                           shift_start=time(9, 30), shift_end=time(18, 30))
            ]
            
            for schedule in schedules:
                db.session.add(schedule)
        
        db.session.commit()
        

        sales_data = [
            (today, 1, [(1, 2, Decimal("450.00")), (3, 1, Decimal("280.00"))]),
            (today, 2, [(2, 1, Decimal("520.00"))]),
            (today, 3, [(5, 3, Decimal("380.00")), (7, 5, Decimal("15.00"))]),

            (today - timedelta(days=1), 1, [(4, 1, Decimal("650.00"))]),
            (today - timedelta(days=1), 2, [(1, 1, Decimal("450.00")), (8, 2, Decimal("45.00"))]),
            (today - timedelta(days=1), 6, [(6, 1, Decimal("850.00"))]),

            (today - timedelta(days=2), 3, [(9, 3, Decimal("120.00"))]),
            (today - timedelta(days=2), 4, [(3, 2, Decimal("280.00")), (5, 1, Decimal("380.00"))]),
        ]
        
        for sale_date, employee_id, items in sales_data:
            total_amount = sum(quantity * price for _, quantity, price in items)
            sale = Sale(employee_id=employee_id, sale_date=sale_date, 
                       sale_time=time(14, 30), total_amount=total_amount)
            db.session.add(sale)
            db.session.flush()
            
            for product_id, quantity, unit_price in items:
                sale_item = SaleItem(sale_id=sale.id, product_id=product_id, 
                                   quantity=quantity, unit_price=unit_price, 
                                   total_price=quantity * unit_price)
                db.session.add(sale_item)
        
        db.session.commit()

        deliveries_data = [
            (date(2023, 9, 1), 1, [(1, 10, Decimal("350.00")), (2, 8, Decimal("420.00"))]),
            (date(2023, 9, 5), 2, [(3, 15, Decimal("220.00"))]),
            (date(2023, 9, 10), 3, [(5, 12, Decimal("300.00"))]),
            (date(2023, 9, 15), 4, [(6, 50, Decimal("12.00"))]),
            (date(2025, 8, 22), 5, [(7, 24, Decimal("35.00")), (9, 30, Decimal("120.00"))])
        ]
        
        for delivery_date, contract_id, items in deliveries_data:
            total_amount = sum(quantity * price for _, quantity, price in items)
            delivery = Delivery(contract_id=contract_id, delivery_date=delivery_date, 
                              total_amount=total_amount)
            db.session.add(delivery)
            db.session.flush()
            
            for product_id, quantity, unit_price in items:
                delivery_item = DeliveryItem(delivery_id=delivery.id, product_id=product_id, 
                                           quantity=quantity, unit_price=unit_price, 
                                           total_price=quantity * unit_price)
                db.session.add(delivery_item)
        
        db.session.commit()
        
        print("База даних успішно ініціалізована з тестовими даними!")

if __name__ == '__main__':
    init_database()
