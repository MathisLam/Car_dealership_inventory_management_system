import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-yat-chung-temp-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dealership_dev.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Target Roles: Super Admin, Owner, Co-owner, Senior Staff, Staff, Investor[cite: 1]
    role = db.Column(db.String(20), nullable=False, default='Staff')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vin = db.Column(db.String(17), unique=True, nullable=False)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Available')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    vehicles = Vehicle.query.all()
    return render_template('dashboard.html', vehicles=vehicles)


@app.route('/add_vehicle', methods=['POST'])
@login_required
def add_vehicle():
    vin = request.form.get('vin')
    make = request.form.get('make')
    model = request.form.get('model')
    year = request.form.get('year')
    price = request.form.get('price')

    if not vin or not make or not model or not year or not price:
        flash('All vehicle fields are required.', 'error')
        return redirect(url_for('dashboard'))

    try:
        year_value = int(year)
        price_value = float(price)
    except ValueError:
        flash('Year must be an integer and price must be a number.', 'error')
        return redirect(url_for('dashboard'))

    vehicle = Vehicle(vin=vin, make=make, model=model, year=year_value, price=price_value)
    db.session.add(vehicle)
    db.session.commit()
    flash('Vehicle added successfully.')
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


def create_default_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print('Created default admin user: admin/admin')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()

    app.run(host='0.0.0.0', port=5000, debug=True)
