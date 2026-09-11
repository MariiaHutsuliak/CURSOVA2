from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='authorized_user')  # guest, authorized_user, operator, administrator
    is_active_flag = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    api_history = db.Column(db.JSON, default=list)

    def is_active(self):
        return self.is_active_flag

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_guest(self):
        return self.role == 'guest'

    def is_authorized_user(self):
        return self.role in ['authorized_user', 'operator', 'administrator']

    def is_operator(self):
        return self.role in ['operator', 'administrator']

    def is_administrator(self):
        return self.role == 'administrator'

    def can_view_products(self):
        return self.role in ['guest', 'authorized_user', 'operator', 'administrator']

    def can_send_requests(self):
        return self.role == 'guest' or not self.is_authenticated

    def can_run_queries(self):
        return self.role in ['authorized_user', 'operator', 'administrator']

    def can_create_queries(self):
        return self.role in ['operator', 'administrator']

    def can_manage_employees(self):
        return self.role in ['operator', 'administrator']

    def can_manage_suppliers(self):
        return self.role in ['operator', 'administrator']

    def can_manage_products(self):
        return self.role in ['operator', 'administrator']

    def can_manage_users(self):
        return self.role == 'administrator'

    def can_manage_requests(self):
        return self.role == 'administrator'

    def __repr__(self):
        return f'<User {self.username}>'

class UserRequest(db.Model):
    __tablename__ = 'user_requests'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(256), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    reviewed_at = db.Column(db.DateTime)

    reviewer = db.relationship('User', backref='reviewed_requests')

    def __repr__(self):
        return f'<UserRequest {self.full_name} - {self.status}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class Department(db.Model):
    __tablename__ = 'departments'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)

    employees = db.relationship('Employee', backref='department', lazy=True)
    work_schedules = db.relationship('WorkSchedule', backref='department', lazy=True)
    
    def __repr__(self):
        return f'<Department {self.name}>'

class Employee(db.Model):
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    position = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    hire_date = db.Column(db.Date, nullable=False, default=date.today)
    is_on_vacation = db.Column(db.Boolean, default=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)

    work_schedules = db.relationship('WorkSchedule', backref='employee', lazy=True)
    sales = db.relationship('Sale', backref='employee', lazy=True)
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_manager(self):
        return 'керівник' in self.position.lower()

    def is_deletable(self):
        return not self.sales
    
    def __repr__(self):
        return f'<Employee {self.full_name}>'

class Supplier(db.Model):
    __tablename__ = 'suppliers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_person = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    address = db.Column(db.Text)
    is_deleted = db.Column(db.Boolean, default=False)

    contracts = db.relationship('Contract', backref='supplier', lazy=True)

    def __repr__(self):
        return f'<Supplier {self.name}>'

class Contract(db.Model):
    __tablename__ = 'contracts'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_number = db.Column(db.String(50), nullable=False, unique=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Relationships
    contract_products = db.relationship('ContractProduct', backref='contract', lazy=True)
    deliveries = db.relationship('Delivery', backref='contract', lazy=True)
    
    def __repr__(self):
        return f'<Contract {self.contract_number}>'

class ProductCategory(db.Model):
    __tablename__ = 'product_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)

    products = db.relationship('Product', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<ProductCategory {self.name}>'

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100))
    isbn = db.Column(db.String(20))
    publisher = db.Column(db.String(100))
    publication_date = db.Column(db.Date)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock_quantity = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('product_categories.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)

    # Relationships
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    contract_products = db.relationship('ContractProduct', backref='product', lazy=True)
    delivery_items = db.relationship('DeliveryItem', backref='product', lazy=True)
    sale_items = db.relationship('SaleItem', backref='product', lazy=True)
    
    def __repr__(self):
        return f'<Product {self.name}>'

class ContractProduct(db.Model):
    __tablename__ = 'contract_products'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contracts.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity_per_delivery = db.Column(db.Integer, nullable=False)
    purchase_price = db.Column(db.Numeric(10, 2), nullable=False)
    
    def __repr__(self):
        return f'<ContractProduct {self.contract_id}-{self.product_id}>'

class Delivery(db.Model):
    __tablename__ = 'deliveries'
    
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contracts.id'), nullable=False)
    delivery_date = db.Column(db.Date, nullable=False, default=date.today)
    total_amount = db.Column(db.Numeric(10, 2), default=0)

    delivery_items = db.relationship('DeliveryItem', backref='delivery', lazy=True)
    
    def __repr__(self):
        return f'<Delivery {self.id} on {self.delivery_date}>'

class DeliveryItem(db.Model):
    __tablename__ = 'delivery_items'
    
    id = db.Column(db.Integer, primary_key=True)
    delivery_id = db.Column(db.Integer, db.ForeignKey('deliveries.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    
    def __repr__(self):
        return f'<DeliveryItem {self.product_id}: {self.quantity}>'

class WorkSchedule(db.Model):
    __tablename__ = 'work_schedules'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    work_date = db.Column(db.Date, nullable=False)
    shift_start = db.Column(db.Time, nullable=False)
    shift_end = db.Column(db.Time, nullable=False)
    
    def __repr__(self):
        return f'<WorkSchedule {self.employee_id} on {self.work_date}>'

class Sale(db.Model):
    __tablename__ = 'sales'
    
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    sale_date = db.Column(db.Date, nullable=False, default=date.today)
    sale_time = db.Column(db.Time, nullable=False, default=datetime.now().time)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)

    sale_items = db.relationship('SaleItem', backref='sale', lazy=True)
    
    def __repr__(self):
        return f'<Sale {self.id}: {self.total_amount}>'

class SaleItem(db.Model):
    __tablename__ = 'sale_items'
    
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sales.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    
    def __repr__(self):
        return f'<SaleItem {self.product_id}: {self.quantity}>'
