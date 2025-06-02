from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from dotenv import load_dotenv
import logging
import re

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
password_reset_requests_collection = db.password_reset_requests

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data['role']
        self.password_hash = user_data['password_hash']
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
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
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
    # Always clear any existing session
    session.clear()
    logout_user()
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                flash('Please enter both username and password.', 'danger')
                return redirect(url_for('login'))
            
            user = User.get_by_username(username)
            if not user:
                logger.warning(f"Failed login attempt for non-existent user: {username}")
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password_hash, password):
                # Create new session
                login_user(user)
                # Set session expiry
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=1)
                
                logger.info(f"User {username} logged in successfully")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Failed login attempt for user: {username}")
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('login'))
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))
            
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
        try:
            # Validate required fields
            required_fields = ['title', 'description', 'price', 'cost', 'platform', 'listing_url']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.replace("_", " ").title()} is required.', 'danger')
                    return redirect(url_for('add_listing'))
            
            # Create new listing
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
                'type': request.form.get('type', 'buy'),  # 'buy' or 'sell'
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            # If it's a buy listing, add to inventory
            if new_listing['type'] == 'buy':
                inventory_item = {
                    'name': new_listing['title'],
                    'quantity': 1,
                    'cost_per_unit': new_listing['cost'],
                    'location': request.form.get('location', 'Default'),
                    'last_restock': datetime.utcnow().isoformat(),
                    'notes': f"Added from listing: {new_listing['listing_url']}",
                    'status': 'pending'  # Will be updated when marked as bought
                }
                inventory_id = inventory_collection.insert_one(inventory_item).inserted_id
                new_listing['inventory_id'] = str(inventory_id)
            
            listings_collection.insert_one(new_listing)
            flash('Listing added successfully!', 'success')
            return redirect(url_for('listings'))
            
        except Exception as e:
            logger.error(f"Error adding listing: {str(e)}")
            flash('An error occurred while adding the listing.', 'danger')
            return redirect(url_for('add_listing'))
    
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
                    
                    # If listing has an inventory item, update its status
                    if listing.get('inventory_id'):
                        inventory_collection.update_one(
                            {'_id': ObjectId(listing['inventory_id'])},
                            {
                                '$set': {
                                    'status': 'sold',
                                    'last_updated': datetime.utcnow().isoformat()
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
        flash('You do not have permission to add users', 'danger')
        return redirect(url_for('users'))
        
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('users'))
            
        # Check if username already exists
        if users_collection.find_one({'username': username}):
            flash('Username already exists', 'danger')
            return redirect(url_for('users'))
            
        # Create new user
        user_data = {
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': role,
            'created_at': datetime.utcnow()
        }
        
        users_collection.insert_one(user_data)
        flash('User added successfully', 'success')
        
    except Exception as e:
        app.logger.error(f"Error adding user: {str(e)}")
        flash('An error occurred while adding the user', 'danger')
        
    return redirect(url_for('users'))

@app.route('/edit_user/<user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('users'))
    
    try:
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
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            flash('Username must be 3-20 characters long and can only contain letters, numbers, underscores, and hyphens.', 'danger')
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
        
        logger.info(f"User updated: {username}")
        flash('User updated successfully.', 'success')
        return redirect(url_for('users'))
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        flash('An error occurred while updating the user.', 'danger')
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
def change_language(language):
    if language in ['en', 'fr']:
        session['language'] = language
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/change_theme', methods=['POST'])
def change_theme():
    data = request.get_json()
    if data and 'theme' in data and data['theme'] in ['light', 'dark']:
        session['theme'] = data['theme']
    return jsonify({'success': True})

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

@app.route('/delete_inventory/<item_id>', methods=['POST'])
@login_required
def delete_inventory(item_id):
    try:
        # Check if item exists
        item = inventory_collection.find_one({'_id': ObjectId(item_id)})
        if not item:
            return jsonify({
                'success': False,
                'message': 'Item not found.'
            }), 404

        # Check if item is in any active listings
        active_listings = listings_collection.find({'status': 'active', 'inventory_id': str(item_id)})
        if active_listings.count() > 0:
            return jsonify({
                'success': False,
                'message': 'Cannot delete item that is part of active listings.'
            }), 400

        # Delete the item
        result = inventory_collection.delete_one({'_id': ObjectId(item_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Inventory item {item_id} deleted by user {current_user.id}")
            return jsonify({
                'success': True,
                'message': 'Item deleted successfully.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to delete item.'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting inventory item: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the item.'
        }), 500

@app.route('/delete_marketplace/<marketplace_id>', methods=['POST'])
@login_required
def delete_marketplace(marketplace_id):
    try:
        # Check if marketplace exists
        marketplace = marketplaces_collection.find_one({'_id': ObjectId(marketplace_id)})
        if not marketplace:
            return jsonify({
                'success': False,
                'message': 'Marketplace not found.'
            }), 404

        # Check if marketplace is used in any listings
        active_listings = listings_collection.find({'platform': marketplace['name']})
        if active_listings.count() > 0:
            return jsonify({
                'success': False,
                'message': 'Cannot delete marketplace that has active listings.'
            }), 400

        # Delete the marketplace
        result = marketplaces_collection.delete_one({'_id': ObjectId(marketplace_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Marketplace {marketplace_id} deleted by user {current_user.id}")
            return jsonify({
                'success': True,
                'message': 'Marketplace deleted successfully.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to delete marketplace.'
            }), 500

    except Exception as e:
        logger.error(f"Error deleting marketplace: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the marketplace.'
        }), 500

@app.route('/delete_sale/<sale_id>', methods=['POST'])
@login_required
def delete_sale(sale_id):
    try:
        # Check if sale exists
        sale = sales_collection.find_one({'_id': ObjectId(sale_id)})
        if not sale:
            return jsonify({
                'success': False,
                'message': 'Sale record not found.'
            }), 404

        # Check if user has permission (only admin or creator can delete)
        if current_user.role != 'admin' and str(sale.get('created_by')) != current_user.id:
            return jsonify({
                'success': False,
                'message': 'You do not have permission to delete this sale record.'
            }), 403

        # Start a session for transaction
        with client.start_session() as session:
            with session.start_transaction():
                # Delete the sale record
                sales_collection.delete_one({'_id': ObjectId(sale_id)}, session=session)
                
                # Update the listing status back to active
                listings_collection.update_one(
                    {'_id': ObjectId(sale['listing_id'])},
                    {
                        '$set': {
                            'status': 'active',
                            'updated_at': datetime.utcnow().isoformat()
                        }
                    },
                    session=session
                )
        
        logger.info(f"Sale record {sale_id} deleted by user {current_user.id}")
        return jsonify({
            'success': True,
            'message': 'Sale record deleted successfully.'
        })

    except Exception as e:
        logger.error(f"Error deleting sale record: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the sale record.'
        }), 500

@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    try:
        username = request.form.get('username')
        message = request.form.get('message', '')
        
        if not username:
            flash('Please provide a username', 'danger')
            return redirect(url_for('login'))
            
        user = users_collection.find_one({'username': username})
        if not user:
            flash('Username not found', 'danger')
            return redirect(url_for('login'))
            
        # Create reset request record
        reset_request = {
            'username': username,
            'message': message,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        password_reset_requests_collection.insert_one(reset_request)
        flash('Password reset request has been submitted. An administrator will review your request.', 'success')
        
    except Exception as e:
        app.logger.error(f"Error creating password reset request: {str(e)}")
        flash('An error occurred while processing your request', 'danger')
        
    return redirect(url_for('login'))

@app.route('/password_reset_requests')
@login_required
def password_reset_requests():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    requests = list(password_reset_requests_collection.find().sort('created_at', -1))
    return render_template('password_reset_requests.html', requests=requests)

@app.route('/handle_reset_request/<request_id>', methods=['POST'])
@login_required
def handle_reset_request(request_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        action = request.form.get('action')
        new_password = request.form.get('new_password')
        
        reset_request = password_reset_requests_collection.find_one({'_id': ObjectId(request_id)})
        if not reset_request:
            flash('Reset request not found', 'danger')
            return redirect(url_for('password_reset_requests'))
        
        if action == 'approve' and new_password:
            # Update user's password
            users_collection.update_one(
                {'username': reset_request['username']},
                {'$set': {'password_hash': generate_password_hash(new_password)}}
            )
            
            # Update request status
            password_reset_requests_collection.update_one(
                {'_id': ObjectId(request_id)},
                {
                    '$set': {
                        'status': 'approved',
                        'updated_at': datetime.utcnow(),
                        'handled_by': current_user.id
                    }
                }
            )
            flash('Password reset request approved', 'success')
            
        elif action == 'reject':
            # Update request status
            password_reset_requests_collection.update_one(
                {'_id': ObjectId(request_id)},
                {
                    '$set': {
                        'status': 'rejected',
                        'updated_at': datetime.utcnow(),
                        'handled_by': current_user.id
                    }
                }
            )
            flash('Password reset request rejected', 'success')
            
        else:
            flash('Invalid action or missing new password', 'danger')
            
    except Exception as e:
        app.logger.error(f"Error handling reset request: {str(e)}")
        flash('An error occurred while processing the request', 'danger')
        
    return redirect(url_for('password_reset_requests'))

@app.route('/reports')
@login_required
def reports():
    try:
        # Get date range from query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build date filter
        date_filter = {}
        if start_date and end_date:
            date_filter = {
                'sale_date': {
                    '$gte': start_date,
                    '$lte': end_date
                }
            }
        
        # Get sales data
        sales = list(sales_collection.find(date_filter))
        
        # Calculate statistics
        total_sales = len(sales)
        total_revenue = sum(sale['sale_price'] for sale in sales)
        total_profit = sum(sale['profit'] for sale in sales)
        avg_profit_margin = (total_profit / total_revenue * 100) if total_revenue > 0 else 0
        
        # Get sales by platform
        platform_stats = {}
        for sale in sales:
            platform = sale['platform']
            if platform not in platform_stats:
                platform_stats[platform] = {
                    'count': 0,
                    'revenue': 0,
                    'profit': 0
                }
            platform_stats[platform]['count'] += 1
            platform_stats[platform]['revenue'] += sale['sale_price']
            platform_stats[platform]['profit'] += sale['profit']
        
        # Get sales by month
        monthly_stats = {}
        for sale in sales:
            month = sale['sale_date'][:7]  # YYYY-MM
            if month not in monthly_stats:
                monthly_stats[month] = {
                    'count': 0,
                    'revenue': 0,
                    'profit': 0
                }
            monthly_stats[month]['count'] += 1
            monthly_stats[month]['revenue'] += sale['sale_price']
            monthly_stats[month]['profit'] += sale['profit']
        
        # Sort monthly stats by date
        monthly_stats = dict(sorted(monthly_stats.items()))
        
        return render_template('reports.html',
                             total_sales=total_sales,
                             total_revenue=total_revenue,
                             total_profit=total_profit,
                             avg_profit_margin=avg_profit_margin,
                             platform_stats=platform_stats,
                             monthly_stats=monthly_stats,
                             start_date=start_date,
                             end_date=end_date)
                             
    except Exception as e:
        logger.error(f"Error generating reports: {str(e)}")
        flash('Error generating reports. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/export_report')
@login_required
def export_report():
    try:
        # Get date range from query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build date filter
        date_filter = {}
        if start_date and end_date:
            date_filter = {
                'sale_date': {
                    '$gte': start_date,
                    '$lte': end_date
                }
            }
        
        # Get sales data
        sales = list(sales_collection.find(date_filter))
        
        # Create CSV content
        csv_content = "Date,Platform,Sale Price,Profit,Notes\n"
        for sale in sales:
            csv_content += f"{sale['sale_date']},{sale['platform']},{sale['sale_price']},{sale['profit']},{sale.get('notes', '')}\n"
        
        # Create response
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=sales_report_{datetime.now().strftime("%Y%m%d")}.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting report: {str(e)}")
        flash('Error exporting report. Please try again.', 'danger')
        return redirect(url_for('reports'))

if __name__ == '__main__':
    app.run(debug=True) 