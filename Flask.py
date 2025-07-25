from flask import Flask,request,jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import re
from markupsafe import escape
import os 
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app)
#MONGODB PART
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["honeypotDB"]
collection = db["web_log"]

attack_patterns = {
    "SQL Injection": [r"(?i)(union(\s|%20)select)", r"(?i)or(\s|%20)1=1", r"'--", r"'#", r"' or '1'='1"],
    "Command Injection": [r";\s*rm", r"\|\s*ls", r"&\s*whoami", r"`cat /etc/passwd`"],
    "XSS": [r"<script>", r"onerror=", r"javascript:"],
    "Path Traversal": [r"\.\./", r"%2e%2e%2f"],
}

def detect_attack(username,password):
    attacks_detected = []
    for attack,patterns in attack_patterns.items():
        for pattern in patterns:
            if re.search(pattern,username) or re.search(pattern,password):
                attacks_detected.append(attack)
                break
    return attacks_detected

def classify_risk(attacks):
    if "SQL Injection" in attacks or "Command Injection" in attacks:
        return "High"
    elif "XSS" in attacks or "Path Traversal" in attacks:
        return "Medium"
    elif "Brute Force" in attacks:
        return "Low"
    return "None"

@app.route('/web-log',methods=['POST'])
def log_login():
    data = request.json
    username = escape(data.get('userName', ''))
    password = escape(data.get('password', ''))
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip_address = request.remote_addr

    attacks = detect_attack(username, password)
    risk_level = classify_risk(attacks)
    log_entry = {
        "username": username,
        "password": password,
        "timestamp": timestamp,
        "ip": ip_address,
        "attacks detected":  attacks if attacks else ["None"],
        "risk-level": risk_level
    }

    collection.insert_one(log_entry)
    return jsonify({'status': 'success', 'message': 'Login attempt logged.', 'risk': risk_level, 'attacks': attacks})

if __name__ == "__main__":
    app.run(port=5000)