from pymongo import MongoClient

import os
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)

db = client["banking_db"]  # base de données
users_collection = db["users"]  # collection
accounts_collection = db["accounts"] 
transactions_collection = db["transactions"]
otp_collection = db["otp_codes"]
beneficiaries_collection = db["beneficiaries"]
activity_logs_collection = db["activity_logs"]
support_collection = db["support_messages"]
budgets_collection = db["budgets"]
appointments_collection = db["appointments"]