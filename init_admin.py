from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB
client = MongoClient(os.getenv('MONGODB_URI'))
db = client[os.getenv('MONGODB_DB')]
users_collection = db['users']

def init_admin():
    # Check if admin user exists
    admin = users_collection.find_one({'username': 'admin'})
    
    if not admin:
        # Create admin user
        admin_user = {
            'username': 'admin',
            'password_hash': generate_password_hash('admin'),
            'role': 'admin',
            'created_at': datetime.utcnow()
        }
        users_collection.insert_one(admin_user)
        print("Admin user created successfully!")
        print("Username: admin")
        print("Password: admin")
        print("\nPlease change the admin password after first login!")
    else:
        print("Admin user already exists.")

if __name__ == '__main__':
    init_admin() 