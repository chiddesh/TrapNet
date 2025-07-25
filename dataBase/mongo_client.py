from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["honeypotDB"]
collection = db["ssh_logs"]


def log_attack(event_type, data):
    log = {
        "event-type" : event_type,
        "timestamp" : datetime.utcnow(),
        **data
    }

    collection.insert_one(log)
    print("[+] Logged Event: ", log)

