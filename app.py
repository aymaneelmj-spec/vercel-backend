
#!/usr/bin/env python3
"""
Happy Deal Transit ERP - COMPLETE VERCEL-READY Backend
Version: 4.1-PRODUCTION
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
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-jwt-secret-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Database - Use PostgreSQL on production (Vercel), SQLite for local dev
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or 'sqlite:///hdtransit.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Company Info
    COMPANY_NAME = 'Happy Deal Transit'
    COMPANY_ADDRESS = '9, Plateaux ESSALAM, Casablanca'
    COMPANY_PHONE = '+212 5 22 20 85 94'
    COMPANY_EMAIL = 'contact@hdtransit.com'

# ============ FLASK APP INITIALIZATION ============

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ============ CRITICAL CORS CONFIGURATION FOR VERCEL ============

# Your frontend URLs - Updated to allow ALL Vercel deployments
ALLOWED_ORIGINS = [
    'https://my-erp-frontend-topaz.vercel.app',  # ✅ PERMANENT DOMAIN
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
]

# Initialize CORS - Allow all origins for Vercel deployments
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     max_age=3600
)

# Add CORS headers to every response - UPDATED TO HANDLE VERCEL PREVIEWS
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    
    if origin:
        # Allow all Vercel deployments (*.vercel.app)
        if origin.endswith('.vercel.app'):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        # Allow localhost for development
        elif 'localhost' in origin or '127.0.0.1' in origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        # Allow specific origins
        elif origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        else:
            # Default to production domain
            response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    else:
        # No origin header, use default
        response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

# Handle preflight OPTIONS requests - UPDATED
@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin')
        
        if origin:
            # Allow all Vercel deployments
            if origin.endswith('.vercel.app'):
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
            # Allow localhost
            elif 'localhost' in origin or '127.0.0.1' in origin:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
            # Allow specific origins
            elif origin in ALLOWED_ORIGINS:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
            else:
                response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
        else:
            response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
            
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        response.headers['Access-Control-Max-Age'] = '3600'
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
    original_currency = db.Column(db.String(3), default='MAD')
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
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============ HELPER FUNCTIONS ============

def get_user_from_token():
    try:
        user_id = get_jwt_identity()
        if not user_id:
            return None
        user = User.query.filter_by(id=user_id, status='active').first()
        return user
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

# Exchange rate service
class ExchangeRateService:
    def get_rates(self):
        return {
            'MAD': 1.0,
            'USD': 10.12,
            'EUR': 11.05,
            'GBP': 12.78
        }
    
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
    print(f"Error: {e}")
    traceback.print_exc()
    return jsonify({'error': str(e)}), 500

# ============ ROUTES ============

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'message': 'Happy Deal Transit ERP API',
        'status': 'online',
        'version': '4.1-PRODUCTION',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/test', methods=['GET', 'OPTIONS'])
def test():
    return jsonify({
        'message': 'API is working!',
        'status': 'success',
        'version': '4.1-PRODUCTION',
        'cors_fixed': True,
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

# ============ DATABASE INITIALIZATION ROUTE ============

@app.route('/api/init-db', methods=['GET', 'POST'])
def initialize_database():
    """Manual database initialization endpoint"""
    try:
        print("🔧 Starting database initialization...")
        
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Check if company exists
        existing_company = Company.query.first()
        if existing_company:
            user_count = User.query.count()
            print(f"ℹ️ Database already initialized with {user_count} users")
            return jsonify({
                'message': 'Database already initialized',
                'status': 'success',
                'companies': Company.query.count(),
                'users': user_count
            })
        
        # Create default company
        company = Company(
            name='Happy Deal Transit',
            address='9, Plateaux ESSALAM, Casablanca',
            phone='+212 5 22 20 85 94',
            email='contact@hdtransit.com',
            base_currency='MAD',
            status='active'
        )
        db.session.add(company)
        db.session.flush()
        print(f"✅ Company created with ID: {company.id}")
        
        # Create admin user
        admin_user = User(
            name='Admin User',
            email='admin@hdtransit.com',
            role='admin',
            company_id=company.id,
            status='active'
        )
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        print("✅ Admin user created")
        
        # Create regular user
        regular_user = User(
            name='User Test',
            email='user@hdtransit.com',
            role='user',
            company_id=company.id,
            status='active'
        )
        regular_user.set_password('user123')
        db.session.add(regular_user)
        print("✅ Regular user created")
        
        db.session.commit()
        print("🎉 Database initialization complete!")
        
        return jsonify({
            'message': 'Database initialized successfully!',
            'status': 'success',
            'company_id': company.id,
            'credentials': {
                'admin': {
                    'email': 'admin@hdtransit.com',
                    'password': 'admin123'
                },
                'user': {
                    'email': 'user@hdtransit.com',
                    'password': 'user123'
                }
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        error_trace = traceback.format_exc()
        print(f"❌ Database initialization failed: {error_msg}")
        print(error_trace)
        return jsonify({
            'error': error_msg,
            'message': 'Failed to initialize database',
            'traceback': error_trace
        }), 500

# ============ AUTHENTICATION ============

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
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
        print(f"Login error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
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
    except Exception as e:
        return jsonify({'error': 'Failed to get profile'}), 500

# ============ EXCHANGE RATES ============

@app.route('/api/exchange-rates', methods=['GET'])
def get_exchange_rates():
    try:
        rates = exchange_service.get_rates()
        return jsonify({
            'base_currency': 'MAD',
            'rates': rates,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': 'Failed to get rates'}), 500

# ============ DASHBOARD ============

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        display_currency = request.args.get('currency', 'MAD')
        
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        transactions = Transaction.query.filter_by(company_id=company_id).all()
        
        total_income = sum(
            exchange_service.convert_currency(t.amount, t.currency or 'MAD', display_currency)
            for t in transactions if t.type == 'income'
        )
        
        total_expenses = sum(
            exchange_service.convert_currency(t.amount, t.currency or 'MAD', display_currency)
            for t in transactions if t.type == 'expense'
        )
        
        pending_invoices = Invoice.query.filter_by(
            company_id=company_id, status='pending'
        ).count()
        
        inventory_items = InventoryItem.query.filter_by(company_id=company_id).all()
        inventory_value = sum(
            exchange_service.convert_currency(
                item.quantity * item.unit_price, 
                item.currency or 'MAD', 
                display_currency
            )
            for item in inventory_items
        )
        
        return jsonify({
            'total_income': round(total_income, 2),
            'total_expenses': round(total_expenses, 2),
            'net_profit': round(total_income - total_expenses, 2),
            'pending_invoices': pending_invoices,
            'inventory_value': round(inventory_value, 2),
            'display_currency': display_currency
        })
    except Exception as e:
        print(f"Dashboard error: {e}")
        return jsonify({'error': 'Failed to get dashboard stats'}), 500


# ============ AUTHENTICATION ============

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
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
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
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
    except Exception as e:
        return jsonify({'error': 'Failed to get profile'}), 500

# ============ EXCHANGE RATES ============

@app.route('/api/exchange-rates', methods=['GET'])
def get_exchange_rates():
    try:
        rates = exchange_service.get_rates()
        return jsonify({
            'base_currency': 'MAD',
            'rates': rates,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': 'Failed to get rates'}), 500

# ============ DASHBOARD ============

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        display_currency = request.args.get('currency', 'MAD')
        
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        transactions = Transaction.query.filter_by(company_id=company_id).all()
        
        total_income = sum(
            exchange_service.convert_currency(t.amount, t.currency or 'MAD', display_currency)
            for t in transactions if t.type == 'income'
        )
        
        total_expenses = sum(
            exchange_service.convert_currency(t.amount, t.currency or 'MAD', display_currency)
            for t in transactions if t.type == 'expense'
        )
        
        pending_invoices = Invoice.query.filter_by(
            company_id=company_id, status='pending'
        ).count()
        
        inventory_items = InventoryItem.query.filter_by(company_id=company_id).all()
        inventory_value = sum(
            exchange_service.convert_currency(
                item.quantity * item.unit_price, 
                item.currency or 'MAD', 
                display_currency
            )
            for item in inventory_items
        )
        
        return jsonify({
            'total_income': round(total_income, 2),
            'total_expenses': round(total_expenses, 2),
            'net_profit': round(total_income - total_expenses, 2),
            'pending_invoices': pending_invoices,
            'inventory_value': round(inventory_value, 2),
            'display_currency': display_currency
        })
    except Exception as e:
        print(f"Dashboard error: {e}")
        return jsonify({'error': 'Failed to get dashboard stats'}), 500

@app.route('/api/dashboard/charts', methods=['GET'])
@jwt_required()
def get_chart_data():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        period = request.args.get('period', '6months')
        display_currency = request.args.get('currency', 'MAD')
        
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        end_date = date.today()
        if period == 'weekly':
            start_date = end_date - timedelta(days=7)
        elif period == 'monthly':
            start_date = end_date.replace(day=1)
        elif period == 'yearly':
            start_date = end_date.replace(month=1, day=1)
        else:
            start_date = end_date - timedelta(days=180)
        
        transactions = Transaction.query.filter(
            Transaction.company_id == company_id,
            Transaction.date >= start_date
        ).all()
        
        period_data = {}
        category_data = {}
        
        for t in transactions:
            amount = exchange_service.convert_currency(
                t.amount, t.currency or 'MAD', display_currency
            )
            
            period_key = t.date.strftime('%Y-%m')
            if period_key not in period_data:
                period_data[period_key] = {'period': period_key, 'income': 0, 'expenses': 0}
            
            if t.type == 'income':
                period_data[period_key]['income'] += amount
            else:
                period_data[period_key]['expenses'] += amount
                category = t.category or 'Other'
                category_data[category] = category_data.get(category, 0) + amount
        
        monthly_data = sorted(period_data.values(), key=lambda x: x['period'])
        category_data_array = [
            {'category': cat, 'amount': round(amt, 2)}
            for cat, amt in sorted(category_data.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return jsonify({
            'monthly_data': monthly_data,
            'category_data': category_data_array
        })
    except Exception as e:
        print(f"Chart error: {e}")
        return jsonify({'error': 'Failed to get chart data'}), 500

# ============ TRANSACTIONS ============

@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        transactions = Transaction.query.filter_by(
            company_id=company_id
        ).order_by(Transaction.date.desc()).all()
        
        return jsonify([{
            'id': t.id,
            'company_id': t.company_id,
            'date': t.date.isoformat(),
            'description': t.description,
            'amount': t.amount,
            'currency': t.currency or 'MAD',
            'type': t.type,
            'category': t.category
        } for t in transactions])
    except Exception as e:
        print(f"Get transactions error: {e}")
        return jsonify({'error': 'Failed to get transactions'}), 500


@app.route('/api/transactions', methods=['POST'])
@jwt_required()
def create_transaction():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        company_id = data.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        currency = data.get('currency', 'MAD')
        amount = float(data['amount'])
        amount_mad = exchange_service.convert_currency(amount, currency, 'MAD')
        
        transaction = Transaction(
            company_id=company_id,
            user_id=user.id,
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            description=data['description'],
            amount=amount,
            currency=currency,
            original_currency=currency,
            amount_mad=amount_mad,
            type=data['type'],
            category=data.get('category', ''),
            source=data.get('source', 'manual')
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'message': 'Transaction created',
            'id': transaction.id
        }), 201
    except Exception as e:
        print(f"Create transaction error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create transaction'}), 500

@app.route('/api/transactions/<int:transaction_id>', methods=['PUT'])
@jwt_required()
def update_transaction(transaction_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        transaction = Transaction.query.get_or_404(transaction_id)
        if not can_access_company_data(user, transaction.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        if 'date' in data:
            transaction.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        if 'description' in data:
            transaction.description = data['description']
        if 'amount' in data:
            transaction.amount = float(data['amount'])
        if 'currency' in data:
            transaction.currency = data['currency']
        if 'type' in data:
            transaction.type = data['type']
        if 'category' in data:
            transaction.category = data['category']
        
        transaction.amount_mad = exchange_service.convert_currency(
            transaction.amount, transaction.currency, 'MAD'
        )
        
        db.session.commit()
        return jsonify({'message': 'Transaction updated'})
    except Exception as e:
        print(f"Update error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update transaction'}), 500

@app.route('/api/transactions/<int:transaction_id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(transaction_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        transaction = Transaction.query.get_or_404(transaction_id)
        if not can_access_company_data(user, transaction.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete transaction'}), 500

@app.route('/api/transactions/bulk-import', methods=['POST'])
@jwt_required()
def bulk_import_transactions():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data or not isinstance(data, list):
            return jsonify({'error': 'Invalid data format'}), 400
        
        imported_count = 0
        errors = []
        
        for idx, row in enumerate(data):
            try:
                company_id = row.get('company_id', user.company_id)
                if not can_access_company_data(user, company_id):
                    continue
                
                currency = row.get('currency', 'MAD')
                amount = float(row['amount'])
                amount_mad = exchange_service.convert_currency(amount, currency, 'MAD')
                
                transaction = Transaction(
                    company_id=company_id,
                    user_id=user.id,
                    date=datetime.strptime(row['date'], '%Y-%m-%d').date(),
                    description=row['description'],
                    amount=amount,
                    currency=currency,
                    original_currency=currency,
                    amount_mad=amount_mad,
                    type=row['type'],
                    category=row.get('category', ''),
                    source='bulk_import'
                )
                db.session.add(transaction)
                imported_count += 1
            except Exception as e:
                errors.append(f'Row {idx + 1}: {str(e)}')
        
        if imported_count > 0:
            db.session.commit()
        
        return jsonify({
            'message': 'Bulk import completed',
            'imported_count': imported_count,
            'errors': errors
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Bulk import failed'}), 500

# ============ INVOICES ============

@app.route('/api/invoices', methods=['GET'])
@jwt_required()
def get_invoices():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        invoices = Invoice.query.filter_by(
            company_id=company_id
        ).order_by(Invoice.date_created.desc()).all()
        
        return jsonify([{
            'id': i.id,
            'company_id': i.company_id,
            'invoice_number': i.invoice_number,
            'client_name': i.client_name,
            'client_email': i.client_email,
            'total_amount': i.total_amount,
            'currency': i.currency,
            'date_created': i.date_created.isoformat(),
            'status': i.status
        } for i in invoices])
    except Exception as e:
        return jsonify({'error': 'Failed to get invoices'}), 500

@app.route('/api/invoices', methods=['POST'])
@jwt_required()
def create_invoice():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        company_id = data.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        invoice_number = data.get('invoice_number')
        if not invoice_number:
            count = Invoice.query.filter_by(company_id=company_id).count()
            invoice_number = f"INV-{company_id:03d}-{count + 1:04d}"
        
        invoice = Invoice(
            company_id=company_id,
            invoice_number=invoice_number,
            client_name=data['client_name'],
            client_email=data.get('client_email', ''),
            total_amount=float(data['total_amount']),
            currency=data.get('currency', 'MAD'),
            date_created=datetime.strptime(data['date_created'], '%Y-%m-%d').date(),
            status=data.get('status', 'pending')
        )
        
        db.session.add(invoice)
        db.session.commit()
        
        return jsonify({
            'message': 'Invoice created',
            'id': invoice.id,
            'invoice_number': invoice_number
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create invoice'}), 500

@app.route('/api/invoices/<int:invoice_id>', methods=['PUT'])
@jwt_required()
def update_invoice(invoice_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        invoice = Invoice.query.get_or_404(invoice_id)
        if not can_access_company_data(user, invoice.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        if 'client_name' in data:
            invoice.client_name = data['client_name']
        if 'client_email' in data:
            invoice.client_email = data['client_email']
        if 'total_amount' in data:
            invoice.total_amount = float(data['total_amount'])
        if 'status' in data:
            invoice.status = data['status']
        
        db.session.commit()
        return jsonify({'message': 'Invoice updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update invoice'}), 500

@app.route('/api/invoices/<int:invoice_id>', methods=['DELETE'])
@jwt_required()
def delete_invoice(invoice_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        invoice = Invoice.query.get_or_404(invoice_id)
        if not can_access_company_data(user, invoice.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        db.session.delete(invoice)
        db.session.commit()
        return jsonify({'message': 'Invoice deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete invoice'}), 500

@app.route('/api/invoices/bulk-import', methods=['POST'])
@jwt_required()
def bulk_import_invoices():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data or not isinstance(data, list):
            return jsonify({'error': 'Invalid data format'}), 400
        
        imported_count = 0
        for row in data:
            try:
                company_id = row.get('company_id', user.company_id)
                if not can_access_company_data(user, company_id):
                    continue
                
                invoice_number = row.get('invoice_number')
                if not invoice_number:
                    count = Invoice.query.filter_by(company_id=company_id).count()
                    invoice_number = f"INV-{company_id:03d}-{count + imported_count + 1:04d}"
                
                invoice = Invoice(
                    company_id=company_id,
                    invoice_number=invoice_number,
                    client_name=row['client_name'],
                    client_email=row.get('client_email', ''),
                    total_amount=float(row['total_amount']),
                    currency=row.get('currency', 'MAD'),
                    date_created=datetime.strptime(row['date_created'], '%Y-%m-%d').date(),
                    status=row.get('status', 'pending')
                )
                db.session.add(invoice)
                imported_count += 1
            except:
                continue
        
        if imported_count > 0:
            db.session.commit()
        
        return jsonify({
            'message': 'Bulk import completed',
            'imported_count': imported_count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Bulk import failed'}), 500

# ============ INVENTORY ============

@app.route('/api/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        items = InventoryItem.query.filter_by(company_id=company_id).all()
        
        return jsonify([{
            'id': i.id,
            'company_id': i.company_id,
            'name': i.name,
            'category': i.category,
            'quantity': i.quantity,
            'unit_price': i.unit_price,
            'currency': i.currency,
            'total_value': i.quantity * i.unit_price
        } for i in items])
    except Exception as e:
        return jsonify({'error': 'Failed to get inventory'}), 500

@app.route('/api/inventory', methods=['POST'])
@jwt_required()
def create_inventory_item():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        company_id = data.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        item = InventoryItem(
            company_id=company_id,
            name=data['name'],
            category=data.get('category', ''),
            quantity=int(data['quantity']),
            unit_price=float(data['unit_price']),
            currency=data.get('currency', 'MAD')
        )
        
        db.session.add(item)
        db.session.commit()
        
        return jsonify({
            'message': 'Inventory item created',
            'id': item.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create item'}), 500

@app.route('/api/inventory/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_inventory_item(item_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        item = InventoryItem.query.get_or_404(item_id)
        if not can_access_company_data(user, item.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        if 'name' in data:
            item.name = data['name']
        if 'category' in data:
            item.category = data['category']
        if 'quantity' in data:
            item.quantity = int(data['quantity'])
        if 'unit_price' in data:
            item.unit_price = float(data['unit_price'])
        if 'currency' in data:
            item.currency = data['currency']
        
        db.session.commit()
        return jsonify({'message': 'Item updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update item'}), 500

@app.route('/api/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_inventory_item(item_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        item = InventoryItem.query.get_or_404(item_id)
        if not can_access_company_data(user, item.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete item'}), 500

@app.route('/api/inventory/bulk-import', methods=['POST'])
@jwt_required()
def bulk_import_inventory():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data or not isinstance(data, list):
            return jsonify({'error': 'Invalid data format'}), 400
        
        imported_count = 0
        for row in data:
            try:
                company_id = row.get('company_id', user.company_id)
                if not can_access_company_data(user, company_id):
                    continue
                
                item = InventoryItem(
                    company_id=company_id,
                    name=row['name'],
                    category=row.get('category', ''),
                    quantity=int(row['quantity']),
                    unit_price=float(row['unit_price']),
                    currency=row.get('currency', 'MAD')
                )
                db.session.add(item)
                imported_count += 1
            except:
                continue
        
        if imported_count > 0:
            db.session.commit()
        
        return jsonify({
            'message': 'Bulk import completed',
            'imported_count': imported_count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Bulk import failed'}), 500

# ============ DATA ENTRIES ============

@app.route('/api/data-entries', methods=['GET'])
@jwt_required()
def get_data_entries():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        query = DataEntry.query.filter_by(company_id=company_id)
        if not is_admin(user):
            query = query.filter_by(user_id=user.id)
        
        entries = query.order_by(DataEntry.created_at.desc()).all()
        
        return jsonify([{
            'id': e.id,
            'company_id': e.company_id,
            'user_id': e.user_id,
            'entry_type': e.entry_type,
            'title': e.title,
            'description': e.description,
            'data': json.loads(e.data) if e.data else [],
            'status': e.status,
            'created_at': e.created_at.isoformat()
        } for e in entries])
    except Exception as e:
        return jsonify({'error': 'Failed to get data entries'}), 500

@app.route('/api/data-entries', methods=['POST'])
@jwt_required()
def create_data_entry():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        company_id = data.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        entry = DataEntry(
            company_id=company_id,
            user_id=user.id,
            entry_type=data['entry_type'],
            title=data.get('title', ''),
            description=data.get('description', ''),
            data=json.dumps(data.get('data', [])),
            status=data.get('status', 'active')
        )
        
        db.session.add(entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Data entry created',
            'id': entry.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create entry'}), 500

@app.route('/api/data-entries/<int:entry_id>', methods=['PUT'])
@jwt_required()
def update_data_entry(entry_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        entry = DataEntry.query.get_or_404(entry_id)
        if not can_access_company_data(user, entry.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        if not is_admin(user) and entry.user_id != user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        if 'title' in data:
            entry.title = data['title']
        if 'description' in data:
            entry.description = data['description']
        if 'data' in data:
            entry.data = json.dumps(data['data'])
        if 'status' in data:
            entry.status = data['status']
        
        entry.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Entry updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update entry'}), 500

@app.route('/api/data-entries/<int:entry_id>', methods=['DELETE'])
@jwt_required()
def delete_data_entry(entry_id):
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        entry = DataEntry.query.get_or_404(entry_id)
        if not can_access_company_data(user, entry.company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        if not is_admin(user) and entry.user_id != user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        db.session.delete(entry)
        db.session.commit()
        return jsonify({'message': 'Entry deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete entry'}), 500

# ============ USER MANAGEMENT ============

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        user = get_user_from_token()
        if not user or not is_admin(user):
            return jsonify({'error': 'Admin access required'}), 403
        
        users = User.query.all()
        
        return jsonify([{
            'id': u.id,
            'name': u.name,
            'email': u.email,
            'role': u.role,
            'status': u.status,
            'company_id': u.company_id,
            'created_at': u.created_at.isoformat()
        } for u in users])
    except Exception as e:
        return jsonify({'error': 'Failed to get users'}), 500

@app.route('/api/users', methods=['POST'])
@jwt_required()
def create_user():
    try:
        user = get_user_from_token()
        if not user or not is_admin(user):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        existing = User.query.filter_by(email=data['email']).first()
        if existing:
            return jsonify({'error': 'Email already exists'}), 400
        
        new_user = User(
            name=data['name'],
            email=data['email'],
            role=data.get('role', 'user'),
            company_id=data.get('company_id', user.company_id),
            status=data.get('status', 'active')
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User created',
            'id': new_user.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    try:
        current_user = get_user_from_token()
        if not current_user or not is_admin(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        target_user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'name' in data:
            target_user.name = data['name']
        if 'email' in data:
            target_user.email = data['email']
        if 'role' in data:
            target_user.role = data['role']
        if 'status' in data:
            target_user.status = data['status']
        if 'password' in data:
            target_user.set_password(data['password'])
        
        db.session.commit()
        return jsonify({'message': 'User updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    try:
        current_user = get_user_from_token()
        if not current_user or not is_admin(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        if user_id == current_user.id:
            return jsonify({'error': 'Cannot delete yourself'}), 403
        
        target_user = User.query.get_or_404(user_id)
        db.session.delete(target_user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/users/<int:user_id>/view', methods=['GET'])
@jwt_required()
def view_user_data(user_id):
    try:
        current_user = get_user_from_token()
        if not current_user or not is_admin(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        target_user = User.query.get_or_404(user_id)
        company_id = target_user.company_id
        
        transactions = Transaction.query.filter_by(company_id=company_id).limit(100).all()
        invoices = Invoice.query.filter_by(company_id=company_id).limit(50).all()
        inventory = InventoryItem.query.filter_by(company_id=company_id).limit(50).all()
        
        return jsonify({
            'user': {
                'id': target_user.id,
                'name': target_user.name,
                'email': target_user.email,
                'role': target_user.role,
                'company_id': target_user.company_id
            },
            'transactions': [{
                'id': t.id,
                'date': t.date.isoformat(),
                'description': t.description,
                'amount': t.amount,
                'currency': t.currency,
                'type': t.type
            } for t in transactions[:20]],
            'invoices': [{
                'id': i.id,
                'invoice_number': i.invoice_number,
                'client_name': i.client_name,
                'total_amount': i.total_amount,
                'status': i.status
            } for i in invoices[:20]]
        })
    except Exception as e:
        return jsonify({'error': 'Failed to get user data'}), 500

# ============ COMPANIES ============

@app.route('/api/companies', methods=['GET'])
@jwt_required()
def get_companies():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if is_admin(user):
            companies = Company.query.all()
        else:
            companies = Company.query.filter_by(id=user.company_id).all()
        
        return jsonify([{
            'id': c.id,
            'name': c.name,
            'address': c.address,
            'phone': c.phone,
            'email': c.email,
            'base_currency': c.base_currency,
            'status': c.status
        } for c in companies])
    except Exception as e:
        return jsonify({'error': 'Failed to get companies'}), 500

# ============ AI ROUTES ============

@app.route('/api/ai/insights', methods=['GET'])
@jwt_required()
def get_ai_insights():
    try:
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        company_id = request.args.get('company_id', user.company_id)
        if not can_access_company_data(user, company_id):
            return jsonify({'error': 'Access denied'}), 403
        
        # Simple insights without AI library
        return jsonify({
            "anomalies": [],
            "anomaly_count": 0,
            "forecast_next_30_days_avg": 0,
            "ai_enabled": False,
            "message": "AI features not available in this version"
        })
    except Exception as e:
        return jsonify({'error': 'Failed to get insights'}), 500

@app.route('/api/ai/categorize', methods=['POST'])
@jwt_required()
def ai_categorize():
    try:
        data = request.get_json()
        description = data.get('description', '').lower()
        
        # Simple rule-based categorization
        if any(word in description for word in ['transport', 'taxi', 'uber']):
            category = 'Transport'
        elif any(word in description for word in ['carburant', 'essence', 'diesel']):
            category = 'Carburant'
        elif any(word in description for word in ['salaire', 'paie', 'salary']):
            category = 'Salaires'
        else:
            category = 'Other'
        
        return jsonify({
            "category": category,
            "description": data.get('description', ''),
            "ai_enabled": False
        })
    except Exception as e:
        return jsonify({"category": "Other", "ai_enabled": False}), 200

# ============ DATABASE INITIALIZATION ============

def init_db_on_startup():
    """Try to initialize database on startup (silent fail)"""
    try:
        with app.app_context():
            db.create_all()
            if not Company.query.first():
                print("⚠️ Database tables created but empty - visit /api/init-db to initialize")
    except Exception as e:
        print(f"⚠️ Startup DB init warning: {e}")

# ============ VERCEL SERVERLESS HANDLER ============

# Initialize database when not in development
if __name__ != '__main__':
    try:
        init_db_on_startup()
    except:
        pass

# For local development
if __name__ == '__main__':
    init_db_on_startup()
    print("=" * 60)
    print("🚀 Starting Happy Deal Transit ERP Backend")
    print("=" * 60)
    print("🌐 Running on: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)#   D e p l o y m e n t   t r i g g e r 
 
 