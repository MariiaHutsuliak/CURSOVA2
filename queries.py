from models import *
from sqlalchemy import func, and_, or_, extract, desc
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta

class BookstoreQueries:
    
    @staticmethod
    def query_1_employees_info(department_name=None, managers_only=False, on_vacation_only=False):
        query = db.session.query(Employee).join(Department)
        
        if department_name:
            query = query.filter(Department.name == department_name)
        
        if managers_only:
            query = query.filter(Employee.position.like('%керівник%'))
        
        if on_vacation_only:
            query = query.filter(Employee.is_on_vacation == True)
        
        return query.all()
    
    @staticmethod
    def query_2_revenue_analysis(start_date=None, end_date=None, category_name=None):
        if not start_date:
            today = date.today()
            start_date = date(today.year, today.month, 1)
            if today.month == 12:
                end_date = date(today.year + 1, 1, 1) - timedelta(days=1)
            else:
                end_date = date(today.year, today.month + 1, 1) - timedelta(days=1)
        
        query = db.session.query(
            func.sum(SaleItem.total_price).label('total_revenue')
        ).join(Sale).join(Product)
        
        if category_name:
            query = query.join(ProductCategory).filter(ProductCategory.name == category_name)
        
        query = query.filter(
            and_(Sale.sale_date >= start_date, Sale.sale_date <= end_date)
        )
        
        result = query.first()
        return result.total_revenue if result.total_revenue else 0

    @staticmethod
    def query_3_contracts_by_period(period_type='month'):
        today = date.today()

        if period_type == 'week':
            start_date = today - timedelta(days=today.weekday())
            end_date = start_date + timedelta(days=6)

        elif period_type == 'month':
            start_date = date(today.year, today.month, 1)
            end_date = (start_date + relativedelta(months=1)) - timedelta(days=1)

        elif period_type == 'quarter':
            quarter = (today.month - 1) // 3 + 1
            start_date = date(today.year, (quarter - 1) * 3 + 1, 1)
            end_date = (start_date + relativedelta(months=3)) - timedelta(days=1)

        elif period_type == 'year':
            start_date = date(today.year, 1, 1)
            end_date = date(today.year, 12, 31)

        query = db.session.query(Contract).filter(
            Contract.start_date.between(start_date, end_date)
        )

        return query.all()

    @staticmethod
    def query_4_suppliers_without_board_games():
        board_games_category = db.session.query(ProductCategory).filter(
            ProductCategory.name.like('%настільн%')
        ).first()
        
        if not board_games_category:
            return db.session.query(Supplier).all()
        
        suppliers_with_board_games = db.session.query(Supplier.id).join(Contract).join(
            ContractProduct
        ).join(Product).filter(
            Product.category_id == board_games_category.id
        ).subquery()
        
        query = db.session.query(Supplier).filter(
            ~Supplier.id.in_(suppliers_with_board_games)
        )
        
        return query.all()
    
    @staticmethod
    def query_5_top_sellers(min_amount=200, period_type='day', target_date=None):
        if not target_date:
            target_date = date.today()
        
        if period_type == 'day':
            start_date = end_date = target_date
        elif period_type == 'week':
            start_date = target_date - timedelta(days=target_date.weekday())
            end_date = start_date + timedelta(days=6)
        elif period_type == 'month':
            start_date = date(target_date.year, target_date.month, 1)
            end_date = (start_date + relativedelta(months=1)) - timedelta(days=1)
        
        query = db.session.query(
            Employee,
            func.sum(Sale.total_amount).label('total_sales'),
            func.count(Sale.id).label('sales_count')
        ).join(Sale).filter(
            and_(Sale.sale_date >= start_date, Sale.sale_date <= end_date)
        ).group_by(Employee.id)
        
        if min_amount:
            query = query.having(func.sum(Sale.total_amount) > min_amount)
        
        return query.all()

    @staticmethod
    def query_6_sales_info(target_date=None, month=None, category_name=None, supplier_name=None):
        query = (
            db.session.query(Sale, SaleItem, Product, ProductCategory)
            .join(SaleItem, SaleItem.sale_id == Sale.id)
            .join(Product, Product.id == SaleItem.product_id)
            .join(ProductCategory, ProductCategory.id == Product.category_id)
        )

        if target_date:
            query = query.filter(Sale.sale_date == target_date)

        if month:
            query = query.filter(extract('month', Sale.sale_date) == month)

        if category_name:
            query = query.filter(ProductCategory.name == category_name)

        if supplier_name:
            query = (
                query.join(ContractProduct, ContractProduct.product_id == Product.id)
                .join(Contract, Contract.id == ContractProduct.contract_id)
                .join(Supplier, Supplier.id == Contract.supplier_id)
                .filter(Supplier.name == supplier_name)
            )

        return query.all()

    @staticmethod
    def query_7_employee_count(target_date=None, department_name=None):
        if not target_date:
            return {'employees': [], 'count': 0}

        query = (
            db.session.query(Employee, WorkSchedule, Department)
            .select_from(WorkSchedule)
            .join(Employee, Employee.id == WorkSchedule.employee_id)
            .join(Department, Department.id == Employee.department_id)
            .filter(WorkSchedule.work_date == target_date)
        )

        if department_name:
            query = query.filter(Department.name == department_name)

        employees = query.all()

        return {
            'employees': employees,
            'count': len(employees)
        }

    @staticmethod
    def query_8_supplier_by_contract(contract_number):
        result = db.session.query(Supplier, Contract).join(Contract).filter(
            Contract.contract_number == contract_number
        ).first()
        
        return result
    
    @staticmethod
    def query_9_supplier_product_value(supplier_name, target_date=None):
        if not target_date:
            target_date = date.today()
        
        query = db.session.query(
            func.sum(DeliveryItem.total_price).label('total_value')
        ).join(Delivery).join(Contract).join(Supplier).filter(
            and_(
                Supplier.name == supplier_name,
                Delivery.delivery_date <= target_date
            )
        )
        
        result = query.first()
        return result.total_value if result.total_value else 0

    @staticmethod
    def query_10_weekly_sales_analysis(from_date=None):
        if not from_date:
            from_date = date.today()

        start_date = from_date - timedelta(days=7)
        end_date = from_date

        total_query = (
            db.session.query(func.sum(SaleItem.total_price).label('total_sales'))
            .select_from(SaleItem)
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.sale_date >= start_date, Sale.sale_date <= end_date)
        )

        total_result = total_query.first()
        total_sales = total_result.total_sales if total_result.total_sales else 0

        category_query = (
            db.session.query(
                ProductCategory.name,
                func.sum(SaleItem.total_price).label('category_sales')
            )
            .select_from(ProductCategory)
            .join(Product, Product.category_id == ProductCategory.id)
            .join(SaleItem, SaleItem.product_id == Product.id)
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.sale_date >= start_date, Sale.sale_date <= end_date)
            .group_by(ProductCategory.id, ProductCategory.name)
        )

        category_results = category_query.all()

        return {
            'total_sales': total_sales,
            'by_category': category_results,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d')
        }
