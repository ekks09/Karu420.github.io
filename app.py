# app.py — Full Backend for KaruGreenLeaf (Supabase + M-PESA + Admin)
import os
import uuid
import base64
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('SECRET_KEY')

# M-PESA config
CONSUMER_KEY = os.getenv("CONSUMER_KEY")
CONSUMER_SECRET = os.getenv("CONSUMER_SECRET")
PASSKEY = os.getenv("PASSKEY")

BUSINESS_SHORTCODE = "174379"
CALLBACK_URL = "https://yourdomain.com/api/mpesa/callback"

# Init
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# ------------------ MODELS ------------------
class Vendor(db.Model, UserMixin):
    __tablename__ = 'vendors'
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    whatsapp = db.Column(db.String(20))
    company = db.Column(db.String(100))
    image_url = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.String, primary_key=True)
    vendor_id = db.Column(db.String, db.ForeignKey('vendors.id'))
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    base_price = db.Column(db.Numeric)
    category = db.Column(db.String(50))
    image_url = db.Column(db.Text)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.String, primary_key=True)
    vendor_id = db.Column(db.String, db.ForeignKey('vendors.id'))
    phone = db.Column(db.String(20))
    total = db.Column(db.Numeric)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.String, primary_key=True)
    order_id = db.Column(db.String, db.ForeignKey('orders.id'))
    product_id = db.Column(db.String, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return Vendor.query.get(user_id)

# ------------------ AUTH ------------------
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = Vendor.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({"success": True, "user": user.username, "is_admin": user.is_admin})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})

# ------------------ VENDORS ------------------
@app.route('/api/vendors', methods=['GET'])
def get_vendors():
    vendors = Vendor.query.filter_by(is_admin=False).all()
    return jsonify([{
        'id': v.id,
        'username': v.username,
        'company': v.company,
        'phone': v.phone,
        'image_url': v.image_url
    } for v in vendors])

# ------------------ PRODUCTS ------------------
@app.route('/api/products', methods=['GET'])
def get_products():
    vendor_id = request.args.get('vendor_id')
    products = Product.query.filter_by(vendor_id=vendor_id).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'base_price': float(p.base_price),
        'category': p.category,
        'image_url': p.image_url
    } for p in products])

# ------------------ ORDER PLACEMENT ------------------
@app.route('/api/orders', methods=['POST'])
def place_order():
    data = request.json
    order_id = str(uuid.uuid4())
    order = Order(
        id=order_id,
        vendor_id=data['vendor_id'],
        phone=data['phone'],
        total=data['total'],
        notes=data.get('notes')
    )
    db.session.add(order)
    for item in data['items']:
        db.session.add(OrderItem(
            id=str(uuid.uuid4()),
            order_id=order_id,
            product_id=item['product_id'],
            quantity=item['quantity']
        ))
    db.session.commit()
    return jsonify({"success": True, "order_id": order_id})

# ------------------ M-PESA STK PUSH (LIVE) ------------------
@app.route('/api/mpesa/initiate', methods=['POST'])
def mpesa_stk():
    data = request.json
    access_token = get_mpesa_token()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{BUSINESS_SHORTCODE}{PASSKEY}{timestamp}".encode()).decode()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    body = {
        "BusinessShortCode": BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(data['amount']),
        "PartyA": data['phone'],
        "PartyB": BUSINESS_SHORTCODE,
        "PhoneNumber": data['phone'],
        "CallBackURL": CALLBACK_URL,
        "AccountReference": "KaruOrder",
        "TransactionDesc": "KaruGreenLeaf Payment"
    }
    r = requests.post("https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest", headers=headers, json=body)
    return jsonify(r.json())

def get_mpesa_token():
    credentials = f"{CONSUMER_KEY}:{CONSUMER_SECRET}"
    encoded = base64.b64encode(credentials.encode()).decode()
    r = requests.get(
        "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        headers={"Authorization": f"Basic {encoded}"}
    )
    return r.json().get("access_token")

# ------------------ ADMIN ROUTES ------------------
@app.route('/api/admin/vendors', methods=['POST'])
@login_required
def add_vendor():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    if Vendor.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username exists'}), 400
    new_vendor = Vendor(
        id=str(uuid.uuid4()),
        username=data['username'],
        password=bcrypt.generate_password_hash(data['password']).decode(),
        company=data['company'],
        phone=data['phone'],
        whatsapp=data['whatsapp'],
        image_url=data.get('image_url')
    )
    db.session.add(new_vendor)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/products', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    new_product = Product(
        id=str(uuid.uuid4()),
        vendor_id=data['vendor_id'],
        name=data['name'],
        description=data['description'],
        base_price=data['base_price'],
        category=data['category'],
        image_url=data.get('image_url')
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'success': True})

# ------------------ INIT & SEED ------------------
@app.route('/init')
def init():
    db.create_all()
    if not Vendor.query.filter_by(username="admin").first():
        admin = Vendor(
            id=str(uuid.uuid4()),
            username="admin",
            password=bcrypt.generate_password_hash("admin123").decode(),
            phone="+254700000000",
            whatsapp="+254700000000",
            company="Admin",
            is_admin=True
        )
        db.session.add(admin)
        # Seed test vendor
        vendor = Vendor(
            id=str(uuid.uuid4()),
            username="vendor1",
            password=bcrypt.generate_password_hash("vendorpass").decode(),
            phone="+254712345678",
            whatsapp="+254712345678",
            company="Shash Empire"
        )
        db.session.add(vendor)
        # Seed product
        db.session.add(Product(
            id=str(uuid.uuid4()),
            vendor_id=vendor.id,
            name="Shash OG",
            description="Top quality shash",
            base_price=1000,
            category="Shash",
            image_url="https://example.com/shash.jpg"
        ))
    db.session.commit()
    return 'Database initialized & seeded.'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
