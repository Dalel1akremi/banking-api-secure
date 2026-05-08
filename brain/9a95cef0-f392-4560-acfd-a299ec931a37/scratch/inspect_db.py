from pymongo import MongoClient
import os

client = MongoClient("mongodb://localhost:27017")
db = client["banking_db"]
users_col = db["users"]
accounts_col = db["accounts"]

print("--- USERS ---")
for user in users_col.find():
    print(f"ID: {user['_id']} | Email: {user.get('email')} | Sub: {user.get('sub')}")

print("\n--- ACCOUNTS ---")
for acc in accounts_col.find():
    print(f"Account: {acc.get('account_number')} | OwnerID: {acc.get('owner_id')}")
