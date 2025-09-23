from flask import Flask, request, jsonify
from pymongo import MongoClient, errors
from flask_cors import CORS
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timezone, timedelta
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

    existing_indexes = collection.index_information()
    if "ip_address_1" not in existing_indexes:
        collection.create_index("ip_address")
    if "timestamp_utc_1" not in existing_indexes:
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

SESSION_WINDOW = 5  # 5 minutes

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

def deduce_intent(session_requests):
    """Deduce attacker intent based on session behavior"""
    request_count = len(session_requests)
    attack_count = sum(len(r['attacks_detected']) for r in session_requests)
    if request_count > 10 and attack_count == 0:
        return "Reconnaissance"
    if attack_count > 0 and request_count <= 10:
        return "Exploitation"
    if request_count > 10 and attack_count > 0:
        return "Scanning"
    return "Normal"

def compute_session_risk(session_requests):
    """Aggregate risk over a session"""
    risk_levels = {"None": 0, "Low": 1, "Medium": 2, "High": 3}
    max_risk = max([risk_levels[r['risk_score']] for r in session_requests], default=0)
    reverse_risk_levels = {v: k for k, v in risk_levels.items()}
    return reverse_risk_levels[max_risk]

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

    timestamp_utc = datetime.now(timezone.utc)

    attacks = detect_attack(username, password, raw_body)
    risk = risk_score(attacks)

    window_start = timestamp_utc - timedelta(minutes=SESSION_WINDOW)
    session_requests = list(collection.find({
        "ip_address": ip_address,
        "timestamp_utc": {"$gte": window_start.isoformat()}
    }))

    session_intent = deduce_intent(session_requests)
    session_risk = compute_session_risk(session_requests)
    session_request_count = len(session_requests)

    log_entry = {
        "_id": str(uuid.uuid4()),
        "timestamp_utc": timestamp_utc.isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent,
        "path": request.path,
        "method": request.method,
        "headers": headers,
        "query_string": query_string,
        "body_raw": raw_body,
        "username": username,
        "password": password,
        "attacks_detected": attacks,
        "risk_score": risk,
        "session_intent": session_intent,
        "session_risk": session_risk,
        "session_request_count": session_request_count
    }

    try:
        collection.insert_one(log_entry)
    except Exception as e:
        logging.exception("Failed to insert log entry")
        return jsonify({"status": "error", "error": str(e)}), 500

    if session_risk == "High":
        logging.warning(f"High-risk session detected from IP {ip_address} ({session_intent})")

    return jsonify(log_entry), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
