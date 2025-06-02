from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB
client = MongoClient(os.getenv('MONGODB_URI'))
db = client[os.getenv('MONGODB_DB')]
users_collection = db['users']

def check_admin():
    # Find admin user
    admin = users_collection.find_one({'username': 'admin'})
    
    if admin:
        print("\nAdmin user found in database:")
        print(f"Username: {admin['username']}")
        print(f"Role: {admin['role']}")
        print(f"Created at: {admin['created_at']}")
        print(f"Has password_hash: {'password_hash' in admin}")
        print("\nDatabase connection successful!")
    else:
        print("Admin user not found in database!")

if __name__ == '__main__':
    check_admin() 