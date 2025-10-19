#!/usr/bin/env python3
"""
Happy Deal Transit ERP - VERCEL PRODUCTION Backend
Version: 4.2-FIXED
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
import os
import json
import traceback

# ============ CONFIGURATION ============

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-jwt-secret'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or 'sqlite:///hdtransit.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

# ============ FLASK APP INITIALIZATION ============

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)

CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     max_age=3600
)

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        if origin.endswith('.vercel.app') or 'localhost' in origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin')
        if origin and (origin.endswith('.vercel.app') or 'localhost' in origin):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        return response, 200

# ============ DATABASE MODELS ============

class Company(db.Model):
    __tablename__ = 'companies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120))
    base_currency = db.Column(db.String(3), default='MAD')
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='company', lazy=True)
    transactions = db.relationship('Transaction', backref='company', lazy=True)
    invoices = db.relationship('Invoice', backref='company', lazy=True)
    inventory_items = db.relationship('InventoryItem', backref='company', lazy=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', index=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date = db.Column(db.Date, nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='MAD')
    amount_mad = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False, index=True)
    category = db.Column(db.String(100))
    source = db.Column(db.String(50), default='manual')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invoice(db.Model):
    __tablename__ = 'invoices'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    invoice_number = db.Column(db.String(50), nullable=False, unique=True)
    client_name = db.Column(db.String(200), nullable=False)
    client_email = db.Column(db.String(120))
    total_amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='MAD')
    date_created = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class InventoryItem(db.Model):
    __tablename__ = 'inventory_items'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    quantity = db.Column(db.Integer, default=0)
    unit_price = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='MAD')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DataEntry(db.Model):
    __tablename__ = 'data_entries'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    entry_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    data = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============ HELPER FUNCTIONS ============

def get_user_from_token():
    try:
        user_id = get_jwt_identity()
        return User.query.filter_by(id=user_id, status='active').first() if user_id else None
    except:
        return None

def is_admin(user):
    return user and user.role in ['admin', 'administrator']

def can_access_company_data(user, company_id):
    if not user:
        return False
    if is_admin(user):
        return True
    try:
        return int(user.company_id) == int(company_id)
    except:
        return False

class ExchangeRateService:
    def get_rates(self):
        return {'MAD': 1.0, 'USD': 10.12, 'EUR': 11.05, 'GBP': 12.78}
    
    def convert_currency(self, amount, from_currency, to_currency):
        if from_currency == to_currency:
            return amount
        rates = self.get_rates()
        if from_currency == 'MAD':
            return amount / rates.get(to_currency, 1)
        elif to_currency == 'MAD':
            return amount * rates.get(from_currency, 1)
        else:
            amount_in_mad = amount * rates.get(from_currency, 1)
            return amount_in_mad / rates.get(to_currency, 1)

exchange_service = ExchangeRateService()

# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    db.session.rollback()
    return jsonify({'error': str(e)}), 500

# ============ ROUTES ============

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'message': 'Happy Deal Transit ERP API',
        'status': 'online',
        'version': '4.2-FIXED',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'message': 'API is working!',
        'status': 'success',
        'version': '4.2-FIXED',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health', methods=['GET'])
def health():
    try:
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        db_status = f'error: {str(e)}'
    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'database': db_status,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/init-db', methods=['GET', 'POST'])
def initialize_database():
    try:
        db.create_all()
        existing_company = Company.query.first()
        if existing_company:
            return jsonify({
                'message': 'Database already initialized',
                'status': 'success',
                'users': User.query.count()
            })
        
        company = Company(
            name='Happy Deal Transit',
            address='9, Plateaux ESSALAM, Casablanca',
            phone='+212 5 22 20 85 94',
            email='contact@hdtransit.com',
            base_currency='MAD'
        )
        db.session.add(company)
        db.session.flush()
        
        admin_user = User(
            name='Admin User',
            email='admin@hdtransit.com',
            role='admin',
            company_id=company.id
        )
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        db.session.commit()
        
        return jsonify({
            'message': 'Database initialized successfully!',
            'status': 'success',
            'credentials': {
                'email': 'admin@hdtransit.com',
                'password': 'admin123'
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email, status='active').first()
        
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            access_token = create_access_token(identity=user.id)
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'role': user.role,
                    'company_id': user.company_id
                }
            })
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user = get_user_from_token()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role,
        'company_id': user.company_id
    })

@app.route('/api/exchange-rates', methods=['GET'])
def get_exchange_rates():
    return jsonify({
        'base_currency': 'MAD',
        'rates': exchange_service.get_rates(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        currency = request.args.get('currency', 'MAD')
        
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        transactions = Transaction.query.filter_by(company_id=company_id).all()
        
        total_income = sum(t.amount for t in transactions if t.type == 'income')
        total_expenses = sum(t.amount for t in transactions if t.type == 'expense')
        pending_invoices = Invoice.query.filter_by(company_id=company_id, status='pending').count()
        
        return jsonify({
            'total_income': round(total_income, 2),
            'total_expenses': round(total_expenses, 2),
            'net_profit': round(total_income - total_expenses, 2),
            'pending_invoices': pending_invoices,
            'inventory_value': 0,
            'display_currency': currency
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ VERCEL HANDLER ============

def init_db_on_startup():
    try:
        with app.app_context():
            db.create_all()
    except:
        pass

if __name__ != '__main__':
    init_db_on_startup()

if __name__ == '__main__':
    init_db_on_startup()
    app.run(host='0.0.0.0', port=5000, debug=True)