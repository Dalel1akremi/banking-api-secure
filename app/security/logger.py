import json
import os
from datetime import datetime
from app.db import activity_logs_collection

LOG_FILE_PATH = "data/ai_activity_logs.json"

def log_activity(user_id: str, account_number: str, action_type: str, status: str, details: dict = None):
    """
    Log user activities for AI anomaly detection, both in MongoDB and local JSON file.
    """
    if details is None:
        details = {}
        
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user_id": user_id,
        "account_number": account_number,
        "action_type": action_type,
        "status": status,
        "details": details
    }
    
    # 1. Store in MongoDB
    try:
        activity_logs_collection.insert_one(log_entry.copy())
    except Exception as e:
        print(f"Error saving log to MongoDB: {e}")
        
    # 2. Append to flat JSON file (Append-only approach for SIEM/AI models)
    try:
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            # We enforce a json lines format (one JSON object per line)
            # Remove _id which might have been added by PyMongo
            log_entry.pop("_id", None)
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error saving log to file: {e}")
