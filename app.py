import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask import session as flask_session, request
from flask_sqlalchemy import SQLAlchemy, session
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

# Initialize Flask App
app = Flask(__name__)

# Basic Configuration
app.config['SECRET_KEY'] = 'dev_super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dealership_dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Roles defined by hierarchy: owner, co_owner, senior_staff, staff, investor, superadmin
    role = db.Column(db.String(20), nullable=False, default='staff') 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    """
    PDPO-Compliant Customer Model (DPP1).
    Strictly limiting data fields to necessary transactional information.
    """
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    # Deliberately omitting excessive background info to ensure compliance with DPP1
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    vin = db.Column(db.String(17), unique=True, nullable=False)
    status = db.Column(db.String(20), default='Available')
    price = db.Column(db.Float, nullable=False)


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False) 
    author = db.relationship('User', backref=db.backref('notices', lazy=True))

class AuditLog(db.Model):
    """
    Tracks user actions to satisfy PDPO DPP4 (Security of Personal Data).
    """
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))


# --- Localization Dictionary ---
TRANSLATIONS = {
    'en': {
        'dashboard': 'Dashboard',
        'add_user': 'Add User',
        'contacts': 'Contacts',
        'logs': 'Logs',
        'logout': 'Logout',
        'unsold_inventory': 'Unsold Inventory',
        'active_tasks': 'Active Tasks',
        'total_sold': 'Total Sold',
        'system_notices': 'System Notices',
        'recent_inventory': 'Recent Inventory',
        'recent_sales': 'Recent Sales',
        'edit_create_item': 'Edit or Create Item',
        'inventory_tab': 'Inventory',
        'notices_tab': 'Notices'
    },
    'zh': {
        'dashboard': '儀表板',
        'add_user': '新增使用者',
        'contacts': '聯絡客戶',
        'logs': '系統日誌',
        'logout': '登出',
        'unsold_inventory': '未售庫存',
        'active_tasks': '進行中任務',
        'total_sold': '總銷量',
        'system_notices': '系統公告',
        'recent_inventory': '最新庫存',
        'recent_sales': '最近售出',
        'edit_create_item': '新增或編輯車輛',
        'inventory_tab': '庫存',
        'notices_tab': '公告'
    }
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Custom RBAC Decorator ---
def requires_roles(*roles):
    """
    Decorator to restrict access based on user roles.
    Superadmins always have access.
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles and current_user.role != 'superadmin':
                flash('Access denied: You do not have the required permissions.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return wrapper

# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            
            # Log the login action
            log = AuditLog(user_id=user.id, action="Logged in")
            db.session.add(log)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log the logout action before destroying the session
    log = AuditLog(user_id=current_user.id, action="Logged out")
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    return redirect(url_for('login'))

@app.route('/add-inventory', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def add_inventory():
    try:
        new_item = Inventory(
            make=request.form.get('make'),
            model=request.form.get('model'),
            year=int(request.form.get('year')),
            vin=request.form.get('vin'),
            price=float(request.form.get('price')),
            status=request.form.get('status')
        )
        db.session.add(new_item)
        
        # Log the inventory addition
        log = AuditLog(user_id=current_user.id, action=f"Added inventory: {new_item.vin}")
        db.session.add(log)
        
        db.session.commit()
        flash('Item added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding item: {str(e)}', 'error')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/mark-sold/<int:item_id>', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def mark_sold(item_id):
    item = Inventory.query.get_or_404(item_id)
    item.status = 'Sold'
    
    log = AuditLog(user_id=current_user.id, action=f"Marked inventory {item.vin} as Sold")
    db.session.add(log)
    db.session.commit()
    
    flash(f'Vehicle {item.make} {item.model} marked as Sold!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/add-customer', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def add_customer():
    name = request.form.get('name')
    contact_number = request.form.get('contact_number')

    if not name or not contact_number:
        flash('Name and contact number are required.', 'error')
        return redirect(url_for('customers'))

    new_customer = Customer(name=name, contact_number=contact_number)
    db.session.add(new_customer)

    log = AuditLog(user_id=current_user.id, action=f"Added customer: {name}")
    db.session.add(log)
    db.session.commit()

    flash('Customer added successfully!', 'success')
    return redirect(url_for('customers'))


@app.route('/edit-customer/<int:customer_id>', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.name = request.form.get('name')
    customer.contact_number = request.form.get('contact_number')

    log = AuditLog(user_id=current_user.id, action=f"Edited customer ID {customer.id}")
    db.session.add(log)
    db.session.commit()

    flash('Customer updated successfully!', 'success')
    return redirect(url_for('customers'))


@app.route('/delete-customer/<int:customer_id>', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff')
def delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    log = AuditLog(user_id=current_user.id, action=f"Deleted customer: {customer.name}")
    db.session.add(log)
    db.session.delete(customer)
    db.session.commit()

    flash('Customer deleted.', 'success')
    return redirect(url_for('customers'))


@app.route('/customers')
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def customers():
    all_customers = Customer.query.order_by(Customer.created_at.desc()).all()

    # Log this access for DPP4 security compliance (consistent with /inventory, /notices)
    access_log = AuditLog(user_id=current_user.id, action="Viewed the customer contact list")
    db.session.add(access_log)
    db.session.commit()

    return render_template('customers.html', user=current_user, customers=all_customers)

@app.route('/add-task', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff', 'staff')
def add_task():
    description = request.form.get('description')
    if description:
        new_task = Task(description=description, assigned_to=current_user.id)
        db.session.add(new_task)
        
        log = AuditLog(user_id=current_user.id, action="Added a new task")
        db.session.add(log)
        
        db.session.commit()
        flash('Task added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/complete-task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Ensure users can only complete their own tasks (unless they are higher ups)
    if task.assigned_to == current_user.id or current_user.role in ['owner', 'co_owner', 'superadmin']:
        task.status = 'Completed'
        
        log = AuditLog(user_id=current_user.id, action=f"Completed task ID {task.id}")
        db.session.add(log)
        db.session.commit()
        
        flash('Task marked as completed!', 'success')
    else:
        flash('You are not authorized to complete this task.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/add-notice', methods=['POST'])
@login_required
@requires_roles('owner', 'co_owner', 'senior_staff') # Restricted to higher level staff
def add_notice():
    content = request.form.get('content')
    if content:
        new_notice = Notice(content=content, user_id=current_user.id)
        db.session.add(new_notice)
        db.session.commit()
        flash("Notice posted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/create-user', methods=['POST'])
@login_required
@requires_roles('owner', 'superadmin')
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('dashboard'))
        
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    
    log = AuditLog(user_id=current_user.id, action=f"Created new user: {username} ({role})")
    db.session.add(log)
    db.session.commit()
    
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('dashboard'))
    
@app.route('/admin/logs')
@login_required
@requires_roles('superadmin')
def view_logs():
    # Fetch the most recent 100 audit logs
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    # Log this admin access for security
    access_log = AuditLog(user_id=current_user.id, action="Viewed system audit logs")
    db.session.add(access_log)
    db.session.commit()
    
    return render_template('logs.html', user=current_user, logs=logs)

@app.route('/dashboard')
@login_required
def dashboard():
    # Sort inventory by ID descending (newest first)
    inventory_items = Inventory.query.order_by(Inventory.id.desc()).all()
    # Only pull Active (Pending) tasks for the dashboard
    tasks = Task.query.filter_by(assigned_to=current_user.id, status='Pending').all()
    sold_items = Inventory.query.filter_by(status='Sold').order_by(Inventory.id.desc()).all()
    
    # Query newest 5 notices
    notices = Notice.query.order_by(Notice.timestamp.desc()).limit(5).all()
    
    return render_template(
        'dashboard.html', 
        user=current_user,
        inventory=inventory_items,
        sold_items=sold_items,
        tasks=tasks,
        notices=notices,
        total_inventory=len([i for i in inventory_items if i.status != 'Sold']), # Count only unsold
        active_tasks=len(tasks),
        monthly_sales=len(sold_items)
    )

# --- CLI Commands ---
@app.cli.command("init-db")
def init_db():
    """Initialize the database and create a superadmin."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='superadmin')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Database initialized and 'admin' account created.")
        else:
            print("Database already initialized.")

# --- Context Processor for Jinja ---
@app.context_processor
def inject_translations():
    lang = flask_session.get('lang', 'en')
    def t(key):
        return TRANSLATIONS.get(lang, {}).get(key, key)
    return dict(t=t, current_lang=lang)

# --- Routes ---

@app.route('/set-lang/<lang>')
def set_lang(lang):
    if lang in ['en', 'zh']:
        flask_session['lang'] = lang
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/inventory')
def inventory():
    try:
        # 1. Check if user is logged in using Flask-Login
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # 2. Audit log for viewing inventory
        new_log = AuditLog(user_id=current_user.id, action="Viewed full inventory directory")
        db.session.add(new_log)
        db.session.commit()
        
        # 3. Load data and render
        inventory_items = Inventory.query.order_by(Inventory.id.desc()).all()
        return render_template('inventory.html', user=current_user, inventory=inventory_items)
        
    except Exception as e:
        print(f"🛑 INVENTORY ROUTE ERROR: {str(e)}")
        flash(f"Could not load Inventory tab: {str(e)}", "error")
        return redirect(url_for('dashboard'))


@app.route('/notices')
def system_notices():
    try:
        # 1. Check if user is logged in using Flask-Login
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # 2. Audit log for viewing notices
        new_log = AuditLog(user_id=current_user.id, action="Viewed full system notices directory")
        db.session.add(new_log)
        db.session.commit()
        
        # 3. Load data and render
        all_notices = Notice.query.order_by(Notice.timestamp.desc()).all()
        return render_template('notices.html', user=current_user, notices=all_notices)
        
    except Exception as e:
        print(f"🛑 NOTICES ROUTE ERROR: {str(e)}")
        flash(f"Could not load Notices tab: {str(e)}", "error")
        return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)