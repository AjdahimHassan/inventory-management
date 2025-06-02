from pymongo import MongoClient
from dotenv import load_dotenv
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def test_mongodb_connection():
    try:
        # Connect to MongoDB
        client = MongoClient(os.getenv('MONGODB_URI'))
        db = client[os.getenv('MONGODB_DB', 'inventory_db')]
        
        # Test connection
        db.command('ping')
        logger.info("Successfully connected to MongoDB!")
        
        # Test collections
        collections = db.list_collection_names()
        logger.info(f"Available collections: {collections}")
        
        # Test users collection
        users = list(db.users.find())
        logger.info(f"Number of users: {len(users)}")
        for user in users:
            logger.info(f"User: {user['username']}, Role: {user.get('role', 'user')}")
        
        return True
    except Exception as e:
        logger.error(f"MongoDB connection test failed: {str(e)}")
        return False

if __name__ == "__main__":
    test_mongodb_connection() 