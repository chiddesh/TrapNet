# app.py
from flask import Flask, request, jsonify
from pymongo import MongoClient, errors
from flask_cors import CORS
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timezone
import uuid
import logging

load_dotenv()
app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("Please set MONGO_URI environment variable")

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client["TrapNet"]
    collection = db["honeypotAttacks"]
    collection.create_index("ip_address")
    collection.create_index("timestamp_utc")
except errors.ServerSelectionTimeoutError as e:
    raise RuntimeError("Could not connect to MongoDB: " + str(e))

attack_patterns = {
    "SQL Injection": [
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)\bor\b\s*1\s*=\s*1\b",
        r"(--|#)\s*$",
        r"(?i)\bselect\b.*\bfrom\b.*\bwhere\b",
    ],
    "Command Injection": [r";\s*rm\b", r"\|\s*ls\b", r"&\s*whoami\b", r"`cat /etc/passwd`"],
    "XSS": [r"(?i)<script\b", r"(?i)on\w+\s*=", r"(?i)javascript:"],
    "Path Traversal": [r"\.\./", r"%2e%2e%2f", r"(?i)\betc/passwd\b"],
}


def detect_attack(username: str, password: str, raw_body: str):
    attacks_detected = []
    subject = " ".join([username or "", password or "", raw_body or ""])
    for attack, patterns in attack_patterns.items():
        for pattern in patterns:
            try:
                if re.search(pattern, subject):
                    attacks_detected.append(attack)
                    break
            except re.error:
                continue
    return attacks_detected


def risk_score(attacks):
    if any(a in attacks for a in ("SQL Injection", "Command Injection")):
        return "High"
    if "XSS" in attacks:
        return "Medium"
    if "Path Traversal" in attacks:
        return "Low"
    return "None"


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/log", methods=["POST"])
def log_attack():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    username = data.get("username", "")
    password = data.get("password", "")

    raw_body = request.get_data(as_text=True)
    headers = dict(request.headers)
    query_string = request.query_string.decode(errors="ignore")
    user_agent = headers.get("User-Agent", "")

    xff = headers.get("X-Forwarded-For", "")
    ip_address = xff.split(",")[0].strip() if xff else request.remote_addr

    timestamp_utc = datetime.now(timezone.utc).isoformat()

    attacks = detect_attack(username, password, raw_body)
    risk = risk_score(attacks)

    log_entry = {
        "_id": str(uuid.uuid4()),
        "timestamp_utc": timestamp_utc,
        "ip_address": ip_address,
        "path": request.path,
        "method": request.method,
        "headers": headers,
        "user_agent": user_agent,
        "query_string": query_string,
        "body_raw": raw_body,
        "username": username,
        "password": password,
        "attacks_detected": attacks,
        "risk_score": risk,
    }

    try:
        collection.insert_one(log_entry)
    except Exception as e:
        logging.exception("Failed to insert log entry")
        return jsonify({"status": "error", "error": str(e)}), 500

    return jsonify({"status": "logged", "attacks_detected": attacks, "risk_score": risk}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
