from pymongo import MongoClient
from app.config import settings

client = MongoClient(settings.mongo_uri)
db = client.user_database

def get_user_collection():
    user_collection = db.users
    # Remove documents with null username
    user_collection.delete_many({"username": None})
    user_collection.create_index("username", unique=True)
    return user_collection
