import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initialize Flask App
app = Flask(__name__)

# Basic Configuration
app.config['SECRET_KEY'] = 'dev_super_secret_key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dealership_dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirects to login route if unauthenticated

# --- Database Models ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Roles: Owner, Co-owners, Senior Staff, Staff, Fund Investors, Super Admin
    role = db.Column(db.String(20), nullable=False, default='Staff') 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    vin = db.Column(db.String(17), unique=True, nullable=False)
    status = db.Column(db.String(20), default='Available')
    price = db.Column(db.Float, nullable=False)

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    # Minimized fields for PDPO DPP1 Compliance
    name = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    vehicle_vin = db.Column(db.String(17), db.ForeignKey('inventory.vin'), nullable=False)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    # Redirect root to dashboard if logged in, else to login
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
        
        # Verify user and password
        if user and user.check_password(password):
            login_user(user)
            # Log role assignment access
            print(f"Logged in: {user.username} with role: {user.role}") 
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch real data from the database
    inventory_items = Inventory.query.all()
    tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    
    # Query for sold items specifically
    sold_items = Inventory.query.filter_by(status='Sold').all()
    
    # Calculate stats dynamically
    total_inventory = len(inventory_items)
    active_tasks = len(tasks)
    # Monthly sales: assuming status 'Sold'
    monthly_sales = len(sold_items)
    
    return render_template(
        'dashboard.html', 
        user=current_user,
        inventory=inventory_items,
        sold_items=sold_items,  # Pass this variable to the template
        tasks=tasks,
        total_inventory=total_inventory,
        active_tasks=active_tasks,
        monthly_sales=monthly_sales
    )

if __name__ == '__main__':
    # Initialize the database and create a default admin user on first run
    with app.app_context():
        db.create_all()
        # Create a Super Admin if none exists for manual role allocation
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='Super Admin')
            admin_user.set_password('admin123') # Change default password immediately
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin created: admin / admin123")
            
    # Run the server
    app.run(debug=True)