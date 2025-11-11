# honeypot.py
from flask import Flask, request, jsonify
from pymongo import MongoClient, errors
from flask_cors import CORS
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timezone, timedelta
import uuid
import logging
import html
from urllib.parse import unquote_plus
import math

load_dotenv()
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("Please set MONGO_URI environment variable")

# --- Mongo setup ---
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client["TrapNet"]
    collection = db["honeypotAttacks"]

    # Ensure indexes (ip_address and timestamp_utc as datetime)
    existing_indexes = collection.index_information()
    if "ip_address_1" not in existing_indexes:
        collection.create_index("ip_address")
    if "timestamp_utc_1" not in existing_indexes:
        collection.create_index([("timestamp_utc", 1)])
except errors.ServerSelectionTimeoutError as e:
    raise RuntimeError("Could not connect to MongoDB: " + str(e))

# --- Config ---
SESSION_WINDOW = 5  # minutes to consider for session aggregation
MAX_PAYLOAD_SIZE = 200000  # bytes; treat bigger as suspicious
SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "acunetix", "curl", "wget", "python-requests", "masscan", "nmap",
    "fuzz", "zap", "burp"
]

# --- Detection patterns (compiled) ---
attack_patterns = {
    "SQL Injection": [
        re.compile(r"(?i)\bunion\b[\s\S]{0,200}\bselect\b"),        # union select
        re.compile(r"(?i)\bor\b\s*1\s*=\s*1\b"),                    # or 1=1
        re.compile(r"(?i)\bselect\b[\s\S]{0,200}\bfrom\b"),        # select ... from
        re.compile(r"(?i)\bexec\b\s*\("),                          # exec(...)
        re.compile(r"(?i)benchmark\(|sleep\(|waitfor\s+delay", re.I),  # time-based
        re.compile(r"(?i)information_schema"),                     # schema enumeration
        re.compile(r"(?i)\bconcat\("),
    ],
    "Command Injection": [
        re.compile(r";\s*(rm|sudo|shutdown|reboot|useradd|adduser)\b"),
        re.compile(r"\|\s*(ls|whoami|cat|curl|wget)\b"),
        re.compile(r"&\s*(whoami|id)\b"),
        re.compile(r"`[^`]{1,200}`"),  # backtick commands
    ],
    "XSS": [
        re.compile(r"(?i)<script\b"),
        re.compile(r"(?i)on\w+\s*="),
        re.compile(r"(?i)javascript:"),
        re.compile(r"(?i)<img[^>]+onerror="),
    ],
    "Path Traversal": [
        re.compile(r"\.\./"),
        re.compile(r"%2e%2e%2f", re.I),
        re.compile(r"(?i)\betc/passwd\b"),
    ],
    "NoSQL Injection": [
        re.compile(r'"\$ne"\s*:'),  # "$ne": ...
        re.compile(r'\$where\b'),
        re.compile(r'"\$gt"\s*:'), 
        re.compile(r'"\$regex"\s*:'), 
    ],
    "Scanner UA": [
        # we'll check substrings for scanner UAs separately
    ],
}

# Severity base scores for detected categories (0-100 scale components)
BASE_SEVERITY = {
    "SQL Injection": 40,
    "Command Injection": 45,
    "XSS": 20,
    "Path Traversal": 10,
    "NoSQL Injection": 30,
    "Malformed JSON": 25,
    "Large Payload": 15,
    "Binary Data": 10,
    "Scanner UA": 20,
    "High Request Rate": 25,
}

# Helper: canonicalize input (URL/HTML decode, lower-case)
def canonicalize(s: str) -> str:
    if not s:
        return ""
    try:
        # unquote percent-encoding then unescape HTML entities
        t = unquote_plus(s)
        t = html.unescape(t)
        return t
    except Exception:
        return s

# Helper: approximate entropy to detect high-entropy payloads (possible obfuscation)
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

# Detect attacks, return found list + details
def detect_attacks_and_reasons(username: str, password: str, raw_body: str, headers: dict):
    reasons = []
    subject = " ".join([username or "", password or "", raw_body or ""])
    canonical = canonicalize(subject)

    # Check each pattern set
    for attack, patterns in attack_patterns.items():
        if attack == "Scanner UA":
            continue
        for pat in patterns:
            try:
                if pat.search(canonical):
                    reasons.append({"type": attack, "pattern": pat.pattern})
                    break
            except re.error as e:
                logging.debug(f"Regex error for {attack}: {e}")
                continue

    # NoSQL operator detection (also check raw JSON form)
    try:
        if re.search(r'"\$[^"]+"\s*:', raw_body):
            reasons.append({"type": "NoSQL Injection", "pattern": "mongo-operator"})
    except Exception:
        pass

    # User-Agent checks
    ua = headers.get("User-Agent", "") or ""
    for sig in SUSPICIOUS_USER_AGENTS:
        if sig.lower() in ua.lower():
            reasons.append({"type": "Scanner UA", "pattern": sig})
            break

    # Malformed JSON detection
    malformed = False
    try:
        # request.get_json(force=True, silent=True) was used earlier;
        # here we attempt a strict parse to catch broken JSON
        import json
        json.loads(raw_body or "{}")
    except Exception:
        malformed = True
        reasons.append({"type": "Malformed JSON", "pattern": "json_parse_error"})

    # Binary / very high-entropy detection
    if any(ord(ch) < 32 for ch in (raw_body or "")) and len(raw_body or "") > 0:
        reasons.append({"type": "Binary Data", "pattern": "control_chars"})
    entropy = shannon_entropy(canonical)
    if entropy > 4.5:
        # high entropy might indicate obfuscated payloads (base64, gzip fragments, shellcode)
        reasons.append({"type": "High Entropy", "pattern": f"entropy={entropy:.2f}"})

    # Large payload
    if len(raw_body.encode('utf-8') if isinstance(raw_body, str) else raw_body) > MAX_PAYLOAD_SIZE:
        reasons.append({"type": "Large Payload", "pattern": f"size={len(raw_body)}"})

    # return unique reason types
    unique_types = []
    unique_reasons = []
    for r in reasons:
        if r["type"] not in unique_types:
            unique_types.append(r["type"])
            unique_reasons.append(r)
    return unique_reasons

# Compute a numeric risk score 0..100 and label
def compute_risk_score(reasons: list, session_requests: list, ip: str):
    # start with 0
    score = 0.0

    # add base severities for each reason type
    for r in reasons:
        t = r["type"]
        score += BASE_SEVERITY.get(t, 5)

    # session-based escalation: recent attack frequency
    recent_attack_count = sum(1 for r in session_requests if r.get("attacks_detected"))
    # scale: if many attacks in session, add more
    if recent_attack_count > 0:
        score += min(30, recent_attack_count * 3)  # cap session bump to 30

    # request rate: if many requests in session window => suspicious
    req_count = len(session_requests)
    if req_count > 20:
        score += 20
    elif req_count > 10:
        score += 10

    # clamp and normalize
    score = max(0.0, min(100.0, score))

    # map to label
    if score >= 75:
        label = "Critical"
    elif score >= 50:
        label = "High"
    elif score >= 25:
        label = "Medium"
    elif score >= 5:
        label = "Low"
    else:
        label = "None"

    return {"score": int(score), "label": label}

# Deduce intent (improved)
def deduce_intent(session_requests):
    request_count = len(session_requests)
    attack_count = sum(1 for r in session_requests if r.get("attacks_detected"))
    if request_count > 15 and attack_count == 0:
        return "Reconnaissance"
    if attack_count > 0 and request_count <= 10:
        return "Exploitation"
    if request_count > 10 and attack_count > 0:
        return "Scanning"
    return "Normal"

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/log", methods=["POST"])
def log_attack():
    # robust raw_body acquisition
    try:
        # keep the original raw bytes string for forensic purposes
        raw_body = request.get_data(as_text=True, parse_form_data=False)
    except Exception as e:
        raw_body = ""
        logging.exception("Failed to read raw body")

    # try to parse JSON leniently to extract username/password
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}

    username = data.get("username", "") if isinstance(data, dict) else ""
    password = data.get("password", "") if isinstance(data, dict) else ""

    headers = dict(request.headers)
    query_string = request.query_string.decode(errors="ignore")
    user_agent = headers.get("User-Agent", "")

    # xff handling - do not blindly trust; we still record it
    xff = headers.get("X-Forwarded-For", "")
    ip_address = xff.split(",")[0].strip() if xff else request.remote_addr

    timestamp_utc = datetime.now(timezone.utc)

    # gather session requests (use timestamp as datetime)
    window_start = timestamp_utc - timedelta(minutes=SESSION_WINDOW)
    try:
        session_requests = list(collection.find({
            "ip_address": ip_address,
            "timestamp_utc": {"$gte": window_start}
        }))
    except Exception:
        session_requests = []
        logging.exception("Failed to fetch session requests from DB")

    # detection
    reasons = detect_attacks_and_reasons(username, password, raw_body, headers)
    # attach concrete attack types for storing
    attack_types = [r["type"] for r in reasons if r["type"] not in ("High Entropy",)]

    # compute numeric risk
    risk_result = compute_risk_score(reasons, session_requests, ip_address)
    session_intent = deduce_intent(session_requests)
    session_risk = compute_session_risk(session_requests) if session_requests else risk_result["label"]
    session_request_count = len(session_requests)

    log_entry = {
        "_id": str(uuid.uuid4()),
        "timestamp_utc": timestamp_utc,  # store as datetime for range queries
        "timestamp_iso": timestamp_utc.isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent,
        "path": request.path,
        "method": request.method,
        "headers": headers,
        "query_string": query_string,
        "body_raw": raw_body[:10000],  # truncate large bodies for storage but keep sample
        "body_size": len(raw_body),
        "username": username,
        "password": password,
        "attacks_detected": attack_types,
        "detection_reasons": reasons,
        "risk": risk_result,
        "session_intent": session_intent,
        "session_risk": session_risk,
        "session_request_count": session_request_count
    }

    # attempt insertion
    try:
        collection.insert_one(log_entry)
    except Exception as e:
        logging.exception("Failed to insert log entry")
        return jsonify({"status": "error", "error": str(e)}), 500

    # alerts/logging
    if risk_result["score"] >= 75:
        logging.error(f"CRITICAL risk {risk_result} from {ip_address} ({session_intent}) reasons: {reasons}")
    elif risk_result["score"] >= 50:
        logging.warning(f"High risk {risk_result} from {ip_address} ({session_intent}) reasons: {reasons}")
    elif risk_result["score"] >= 25:
        logging.info(f"Medium risk {risk_result} from {ip_address} ({session_intent}) reasons: {reasons}")

    return jsonify(log_entry), 201

# compute_session_risk reused, small protective change (works even if DB entries lack 'risk_score')
def compute_session_risk(session_requests):
    risk_levels = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    max_risk = 0
    for r in session_requests:
        # if we stored numeric earlier, use it; else fallback to label
        if isinstance(r.get("risk"), dict) and "score" in r["risk"]:
            score = r["risk"]["score"]
            # map numeric to bucket
            if score >= 75:
                val = 4
            elif score >= 50:
                val = 3
            elif score >= 25:
                val = 2
            elif score >= 5:
                val = 1
            else:
                val = 0
        else:
            val = risk_levels.get(r.get("risk_score") or r.get("risk") or "None", 0)
        if val > max_risk:
            max_risk = val
    reverse = {v: k for k, v in risk_levels.items()}
    return reverse.get(max_risk, "None")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
