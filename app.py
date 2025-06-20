from flask import Flask, jsonify, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vendors.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app, supports_credentials=True)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    whatsapp = db.Column(db.String(20))
    company = db.Column(db.String(100))
    role = db.Column(db.String(20), default='vendor')  # admin or vendor
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200), default='default_vendor.jpg')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200), default='default_product.jpg')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_phone = db.Column(db.String(20), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    products = db.Column(db.Text)  # JSON string of product IDs and quantities
    total = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, shipped, delivered
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize Database
with app.app_context():
    db.create_all()
    # Create initial admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin',
            company='System Admin',
            description='Main administrator account'
        )
        db.session.add(admin)
        db.session.commit()

# Helper Functions
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# Authentication Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if user and check_password_hash(user.password, data['password']):
        session['user_id'] = user.id
        return jsonify({
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'company': user.company
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

# Vendor Management Routes
@app.route('/api/vendors', methods=['GET'])
def get_vendors():
    vendors = User.query.filter_by(role='vendor').all()
    return jsonify([{
        'id': v.id,
        'username': v.username,
        'phone': v.phone,
        'whatsapp': v.whatsapp,
        'company': v.company,
        'description': v.description,
        'image_url': v.image_url,
        'products': Product.query.filter_by(vendor_id=v.id).count()
    } for v in vendors]), 200

@app.route('/api/vendors/<int:id>', methods=['GET'])
def get_vendor(id):
    vendor = User.query.get(id)
    if not vendor or vendor.role != 'vendor':
        return jsonify({'error': 'Vendor not found'}), 404
    
    return jsonify({
        'id': vendor.id,
        'username': vendor.username,
        'phone': vendor.phone,
        'whatsapp': vendor.whatsapp,
        'company': vendor.company,
        'description': vendor.description,
        'image_url': vendor.image_url
    }), 200

@app.route('/api/vendors', methods=['POST'])
def create_vendor():
    if get_current_user() and get_current_user().role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    new_vendor = User(
        username=data['username'],
        password=generate_password_hash(data['password']),
        phone=data['phone'],
        whatsapp=data['whatsapp'],
        company=data['company'],
        role='vendor',
        description=data.get('description', ''),
        image_url=data.get('image_url', 'default_vendor.jpg')
    )
    db.session.add(new_vendor)
    db.session.commit()
    return jsonify({'message': 'Vendor created successfully'}), 201

@app.route('/api/vendors/<int:id>', methods=['PUT'])
def update_vendor(id):
    vendor = User.query.get(id)
    if not vendor:
        return jsonify({'error': 'Vendor not found'}), 404
    
    data = request.json
    if 'username' in data:
        vendor.username = data['username']
    if 'phone' in data:
        vendor.phone = data['phone']
    if 'whatsapp' in data:
        vendor.whatsapp = data['whatsapp']
    if 'company' in data:
        vendor.company = data['company']
    if 'description' in data:
        vendor.description = data['description']
    if 'image_url' in data:
        vendor.image_url = data['image_url']
    
    db.session.commit()
    return jsonify({'message': 'Vendor updated successfully'}), 200

@app.route('/api/vendors/<int:id>', methods=['DELETE'])
def delete_vendor(id):
    if get_current_user() and get_current_user().role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    vendor = User.query.get(id)
    if not vendor or vendor.role != 'vendor':
        return jsonify({'error': 'Vendor not found'}), 404
    
    # Delete associated products
    Product.query.filter_by(vendor_id=id).delete()
    db.session.delete(vendor)
    db.session.commit()
    return jsonify({'message': 'Vendor deleted successfully'}), 200

# Product Management Routes
@app.route('/api/products', methods=['GET'])
def get_products():
    vendor_id = request.args.get('vendor_id')
    if vendor_id:
        products = Product.query.filter_by(vendor_id=vendor_id).all()
    else:
        products = Product.query.all()
    
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'category': p.category,
        'base_price': p.base_price,
        'stock': p.stock,
        'description': p.description,
        'image_url': p.image_url,
        'vendor_id': p.vendor_id
    } for p in products]), 200

@app.route('/api/products', methods=['POST'])
def create_product():
    current_user = get_current_user()
    if not current_user or (current_user.role != 'admin' and current_user.role != 'vendor'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    new_product = Product(
        name=data['name'],
        category=data['category'],
        base_price=data['base_price'],
        vendor_id=current_user.role == 'vendor' and current_user.id or data.get('vendor_id'),
        stock=data.get('stock', 0),
        description=data.get('description', ''),
        image_url=data.get('image_url', 'default_product.jpg')
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201

@app.route('/api/products/<int:id>', methods=['PUT'])
def update_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    current_user = get_current_user()
    if not current_user or (current_user.role != 'admin' and current_user.id != product.vendor_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    if 'name' in data:
        product.name = data['name']
    if 'category' in data:
        product.category = data['category']
    if 'base_price' in data:
        product.base_price = data['base_price']
    if 'stock' in data:
        product.stock = data['stock']
    if 'description' in data:
        product.description = data['description']
    if 'image_url' in data:
        product.image_url = data['image_url']
    
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200

@app.route('/api/products/<int:id>', methods=['DELETE'])
def delete_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    current_user = get_current_user()
    if not current_user or (current_user.role != 'admin' and current_user.id != product.vendor_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

# Order Management Routes
@app.route('/api/orders', methods=['POST'])
def create_order():
    data = request.json
    try:
        new_order = Order(
            customer_phone=data['phone'],
            vendor_id=data['vendor_id'],
            products=data['products'],  # JSON string of {product_id: quantity}
            total=data['total'],
            notes=data.get('notes', '')
        )
        db.session.add(new_order)
        db.session.commit()
        
        # Update product stock
        products = data['products']
        for product_id, quantity in products.items():
            product = Product.query.get(product_id)
            if product:
                product.stock -= int(quantity)
        
        db.session.commit()
        return jsonify({
            'message': 'Order created successfully',
            'order_id': new_order.id
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/orders', methods=['GET'])
def get_orders():
    current_user = get_current_user()
    if not current_user:
        return jsonify({'error': 'Unauthorized'}), 403
    
    vendor_id = request.args.get('vendor_id')
    if current_user.role == 'vendor':
        orders = Order.query.filter_by(vendor_id=current_user.id).all()
    elif vendor_id:
        orders = Order.query.filter_by(vendor_id=vendor_id).all()
    else:
        orders = Order.query.all()
    
    return jsonify([{
        'id': o.id,
        'customer_phone': o.customer_phone,
        'vendor_id': o.vendor_id,
        'products': o.products,
        'total': o.total,
        'notes': o.notes,
        'status': o.status,
        'created_at': o.created_at.isoformat()
    } for o in orders]), 200

@app.route('/api/orders/<int:id>', methods=['PUT'])
def update_order_status(id):
    order = Order.query.get(id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    current_user = get_current_user()
    if not current_user or (current_user.role != 'admin' and current_user.id != order.vendor_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    if 'status' in data and data['status'] in ['pending', 'confirmed', 'shipped', 'delivered']:
        order.status = data['status']
        db.session.commit()
        return jsonify({'message': 'Order status updated successfully'}), 200
    
    return jsonify({'error': 'Invalid status'}), 400

# Redirect for vendor dashboard
@app.route('/vendor-dashboard')
def vendor_dashboard():
    return redirect('vendor_admin_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)