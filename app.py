from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logistics.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # e.g., 'admin', 'partner'

# Shipment model
class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_number = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(100), nullable=False)
    uploaded_document = db.Column(db.String(200))

@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('landing.html')
        # return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    shipments = Shipment.query.all()
    return render_template('dashboard.html', shipments=shipments)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        tracking_number = request.form['tracking_number']
        status = request.form['status']

        # Step 1: Check for duplicate tracking number (Secure Coding)
        existing = Shipment.query.filter_by(tracking_number=tracking_number).first()
        if existing:
            flash('Tracking number already exists. Please use a unique tracking number.')
            return redirect(url_for('upload'))

        new_shipment = Shipment(tracking_number=tracking_number, status=status)

        try:
            db.session.add(new_shipment)
            db.session.commit()
            flash('Shipment created successfully!')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving: {str(e)}')
            return redirect(url_for('upload'))

    return render_template('upload.html')

@app.route('/track', methods=['GET', 'POST'])
def track():
    status = None
    if request.method == 'POST':
        tracking_number = request.form['tracking_number']
        shipment = Shipment.query.filter_by(tracking_number=tracking_number).first()
        if shipment:
            status = shipment.status
        else:
            status = 'Tracking number not found'
    return render_template('track.html', status=status)

if __name__ == '__main__':
  with app.app_context():
    if not os.path.exists('logistics.db'):
        db.create_all()
    app.run(debug=True)
