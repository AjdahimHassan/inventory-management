from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MongoDB setup
try:
    client = MongoClient(os.getenv('MONGODB_URI'))
    db = client[os.getenv('MONGODB_DB', 'inventory_db')]
    # Test the connection
    db.command('ping')
    logger.info("Successfully connected to MongoDB!")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    raise

# Collections
users_collection = db.users
marketplaces_collection = db.marketplaces
listings_collection = db.listings
inventory_collection = db.inventory
sales_collection = db.sales

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data['role']
        self.created_at = user_data.get('created_at', datetime.utcnow())

    @staticmethod
    def get(user_id):
        try:
            user_data = users_collection.find_one({'_id': ObjectId(user_id)})
            if user_data:
                return User(user_data)
            return None
        except Exception as e:
            logging.error(f"Error getting user: {str(e)}")
            return None

    @staticmethod
    def get_by_username(username):
        try:
            user_data = users_collection.find_one({'username': username})
            if user_data:
                return User(user_data)
            return None
        except Exception as e:
            logging.error(f"Error getting user by username: {str(e)}")
            return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Routes
@app.route('/')
@login_required
def dashboard():
    listings = list(listings_collection.find())
    inventory = list(inventory_collection.find())
    sales = list(sales_collection.find())
    
    # Calculate statistics
    total_listings = len(listings)
    active_listings = len([l for l in listings if l['status'] == 'active'])
    total_inventory_value = sum(item['quantity'] * item['cost_per_unit'] for item in inventory)
    total_sales = len(sales)
    total_profit = sum(sale['profit'] for sale in sales)
    
    return render_template('dashboard.html',
                         listings=listings,
                         inventory=inventory,
                         recent_sales=sales[-5:],
                         stats={
                             'total_listings': total_listings,
                             'active_listings': active_listings,
                             'total_inventory_value': total_inventory_value,
                             'total_sales': total_sales,
                             'total_profit': total_profit
                         })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return redirect(url_for('login'))
        
        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/listings')
@login_required
def listings():
    listings = list(listings_collection.find())
    return render_template('listings.html', listings=listings)

@app.route('/add_listing', methods=['GET', 'POST'])
@login_required
def add_listing():
    if request.method == 'POST':
        new_listing = {
            'title': request.form['title'],
            'description': request.form['description'],
            'price': float(request.form['price']),
            'cost': float(request.form['cost']),
            'platform': request.form['platform'],
            'listing_url': request.form['listing_url'],
            'seller_contact': request.form.get('seller_contact', ''),
            'notes': request.form.get('notes', ''),
            'status': 'active',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        listings_collection.insert_one(new_listing)
        flash('Listing added successfully!', 'success')
        return redirect(url_for('listings'))
    
    marketplaces = list(marketplaces_collection.find())
    return render_template('add_listing.html', marketplaces=marketplaces)

@app.route('/inventory')
@login_required
def inventory():
    items = list(inventory_collection.find())
    return render_template('inventory.html', items=items)

@app.route('/add_inventory', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if request.method == 'POST':
        new_item = {
            'name': request.form['name'],
            'quantity': int(request.form['quantity']),
            'cost_per_unit': float(request.form['cost_per_unit']),
            'location': request.form['location'],
            'last_restock': datetime.utcnow().isoformat(),
            'notes': request.form.get('notes', '')
        }
        inventory_collection.insert_one(new_item)
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('add_inventory.html')

@app.route('/sales')
@login_required
def sales():
    sales = list(sales_collection.find())
    return render_template('sales.html', sales=sales)

@app.route('/add_sale', methods=['GET', 'POST'])
@login_required
def add_sale():
    if request.method == 'POST':
        try:
            # Validate required fields
            if not request.form.get('listing_id'):
                flash('Please select a listing.', 'danger')
                return redirect(url_for('add_sale'))
            
            if not request.form.get('sale_price'):
                flash('Please enter a sale price.', 'danger')
                return redirect(url_for('add_sale'))
            
            if not request.form.get('platform'):
                flash('Please enter a platform.', 'danger')
                return redirect(url_for('add_sale'))
            
            # Validate listing exists and is active
            try:
                listing = listings_collection.find_one({'_id': ObjectId(request.form['listing_id'])})
                if not listing:
                    flash('Selected listing not found.', 'danger')
                    return redirect(url_for('add_sale'))
                
                if listing.get('status') != 'active':
                    flash('This listing is no longer active.', 'danger')
                    return redirect(url_for('add_sale'))
            except Exception as e:
                logger.error(f"Error finding listing: {str(e)}")
                flash('Invalid listing selected.', 'danger')
                return redirect(url_for('add_sale'))
            
            # Validate and convert sale price
            try:
                sale_price = float(request.form['sale_price'])
                if sale_price <= 0:
                    flash('Sale price must be greater than 0.', 'danger')
                    return redirect(url_for('add_sale'))
            except ValueError:
                flash('Invalid sale price format.', 'danger')
                return redirect(url_for('add_sale'))
            
            # Calculate profit
            profit = sale_price - listing['cost']
            
            # Create sale record
            new_sale = {
                'listing_id': str(listing['_id']),
                'sale_date': datetime.utcnow().isoformat(),
                'sale_price': sale_price,
                'profit': profit,
                'platform': request.form['platform'],
                'notes': request.form.get('notes', ''),
                'created_by': current_user.id
            }
            
            # Update listing status and record sale in a transaction
            try:
                # Start a session for transaction
                with client.start_session() as session:
                    with session.start_transaction():
                        # Insert sale record
                        sales_collection.insert_one(new_sale, session=session)
                        
                        # Update listing status
                        listings_collection.update_one(
                            {'_id': ObjectId(listing['_id'])},
                            {
                                '$set': {
                                    'status': 'sold',
                                    'updated_at': datetime.utcnow().isoformat()
                                }
                            },
                            session=session
                        )
                
                flash('Sale recorded successfully!', 'success')
                logger.info(f"Sale recorded for listing {listing['_id']} by user {current_user.id}")
                return redirect(url_for('sales'))
                
            except Exception as e:
                logger.error(f"Error recording sale: {str(e)}")
                flash('Error recording sale. Please try again.', 'danger')
                return redirect(url_for('add_sale'))
            
        except Exception as e:
            logger.error(f"Unexpected error in add_sale: {str(e)}")
            flash('An unexpected error occurred. Please try again.', 'danger')
            return redirect(url_for('add_sale'))
    
    # GET request - show form
    try:
        # Get only active listings
        listings = list(listings_collection.find({'status': 'active'}))
        if not listings:
            flash('No active listings available.', 'warning')
        return render_template('add_sale.html', listings=listings)
    except Exception as e:
        logger.error(f"Error fetching listings: {str(e)}")
        flash('Error loading listings. Please try again.', 'danger')
        return redirect(url_for('sales'))

@app.route('/marketplaces')
@login_required
def marketplaces():
    marketplaces = list(marketplaces_collection.find())
    return render_template('marketplaces.html', marketplaces=marketplaces)

@app.route('/add_marketplace', methods=['GET', 'POST'])
@login_required
def add_marketplace():
    if request.method == 'POST':
        new_marketplace = {
            'name': request.form['name'],
            'url': request.form['url'],
            'description': request.form['description'],
            'created_at': datetime.utcnow().isoformat()
        }
        marketplaces_collection.insert_one(new_marketplace)
        flash('Marketplace added successfully!', 'success')
        return redirect(url_for('marketplaces'))
    return render_template('add_marketplace.html')

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = list(users_collection.find())
    return render_template('users.html', users=users)

@app.route('/get_user/<user_id>')
@login_required
def get_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if user:
        user['_id'] = str(user['_id'])
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('users'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('users'))
    
    if users_collection.find_one({'username': username}):
        flash('Username already exists.', 'danger')
        return redirect(url_for('users'))
    
    hashed_password = generate_password_hash(password)
    user = {
        'username': username,
        'password_hash': hashed_password,
        'role': role,
        'created_at': datetime.utcnow()
    }
    
    users_collection.insert_one(user)
    flash('User added successfully.', 'success')
    return redirect(url_for('users'))

@app.route('/edit_user/<user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('users'))
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('users'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if not username:
        flash('Username is required.', 'danger')
        return redirect(url_for('users'))
    
    # Check if username is taken by another user
    existing_user = users_collection.find_one({
        'username': username,
        '_id': {'$ne': ObjectId(user_id)}
    })
    if existing_user:
        flash('Username already exists.', 'danger')
        return redirect(url_for('users'))
    
    update_data = {
        'username': username,
        'role': role
    }
    
    if password:
        update_data['password_hash'] = generate_password_hash(password)
    
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': update_data}
    )
    
    flash('User updated successfully.', 'success')
    return redirect(url_for('users'))

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user['username'] == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete admin user'}), 400
    
    users_collection.delete_one({'_id': ObjectId(user_id)})
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/change_language/<language>')
@login_required
def change_language(language):
    session['language'] = language
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/delete_listing/<listing_id>', methods=['POST'])
@login_required
def delete_listing(listing_id):
    try:
        # Check if listing exists
        listing = listings_collection.find_one({'_id': ObjectId(listing_id)})
        if not listing:
            return jsonify({
                'success': False,
                'message': 'Listing not found.'
            }), 404

        # Check if listing is sold
        if listing.get('status') == 'sold':
            return jsonify({
                'success': False,
                'message': 'Cannot delete a sold listing.'
            }), 400

        # Delete the listing
        result = listings_collection.delete_one({'_id': ObjectId(listing_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Listing {listing_id} deleted by user {current_user.id}")
            return jsonify({
                'success': True,
                'message': 'Listing deleted successfully.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to delete listing.'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting listing: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the listing.'
        }), 500

if __name__ == '__main__':
    app.run(debug=True) 