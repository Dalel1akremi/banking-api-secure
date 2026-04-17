from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")

db = client["banking_db"]  # base de données
users_collection = db["users"]  # collection
accounts_collection = db["accounts"] 
transactions_collection = db["transactions"]
otp_collection = db["otp_codes"]
beneficiaries_collection = db["beneficiaries"]
activity_logs_collection = db["activity_logs"]