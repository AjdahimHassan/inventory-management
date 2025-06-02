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
    
    # Always update admin password to ensure it's correct
    admin_user = {
        'username': 'admin',
        'password_hash': generate_password_hash('Kaneki2005lol!'),
        'role': 'admin',
        'created_at': datetime.utcnow()
    }
    
    if admin:
        # Update existing admin
        users_collection.update_one(
            {'username': 'admin'},
            {'$set': admin_user}
        )
        print("Admin user updated successfully!")
    else:
        # Create new admin
        users_collection.insert_one(admin_user)
        print("Admin user created successfully!")
    
    print("Username: admin")
    print("Password: Kaneki2005lol!")
    print("\nAdmin credentials have been set/updated!")

if __name__ == '__main__':
    init_admin() 