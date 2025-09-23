# TrapNet Honeypot Project
#### Overview

TrapNet is a honeypot web application designed to log attempted attacks on a fake login page. The frontend is built with React + Tailwind CSS, and the backend uses Flask to capture and store attack data in MongoDB Atlas.

This project is intended for educational purposes, allowing you to study attack patterns (SQL Injection, XSS, Path Traversal, etc.) without risking real systems.

#### Features

- Fake login page mimicking a real login interface.

- Logs incoming attacks with:

- Username and password entered

- IP address

- Headers, user agent, query string, raw body

- Detected attack types and risk score

- Responsive design for desktop and mobile.

- Simple risk scoring: High, Medium, Low, None.

- Uses MongoDB Atlas to store logs securely.

Tech Stack
Layer	Technology
Frontend	React, Tailwind CSS, Vite
Backend	Flask, Python
Database	MongoDB Atlas
Dev Tools	dotenv, Flask-CORS, uuid

# Getting Started
1. Clone the repository
```
git clone https://github.com/yourusername/trapnet.git
cd trapnet
```
2. Setup backend

Create a virtual environment:
```
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows
```

Install dependencies:
```
pip install -r requirements.txt
```

Create a .env file in the backend root:
```
MONGO_URI=<your_mongodb_connection_string>
PORT=5000
```

Run the backend:
```
python app.py
```
3. Setup frontend

Navigate to the frontend folder (if separate):
```
cd frontend
```

Install Node dependencies:
```
npm install
```

Create a .env file:
```
VITE_BACKEND_URL=http://localhost:5000
```

Start the dev server:
```
npm run dev
```

Open the URL provided (usually http://localhost:5173) to view the login page.

# How it works

- Users (or attackers) submit credentials via the fake login page.

- Backend inspects the request for attack patterns using regex.

- Backend stores the log in MongoDB with:

    -  Timestamp (UTC)

    - IP address

    - Headers and raw request

    - Detected attack types

    - Risk score

- Logs can be analyzed to understand common attack vectors.

Attack Patterns Detected

    - SQL Injection (e.g., ' OR 1=1 --)

    - Command Injection (e.g., ; rm -rf /)

    - Cross-Site Scripting (XSS) (e.g., <script>alert()</script>)

    - Path Traversal (e.g., ../../etc/passwd)

# Security Notes

- Do not run this on a production server open to the public without protection.

- All passwords and payloads are logged — treat MongoDB as sensitive data.

- Never execute user input; this honeypot only logs attempts.

- Use firewall and IP restrictions if testing outside local network.


# Future Improvements

- Admin dashboard to visualize attacks (top IPs, top attack types).

- Rate-limiting or CAPTCHA to avoid DB flooding.

- Honeytokens or fake API keys to detect misuse elsewhere.

- GeoIP or ASN lookup to enrich log data.

# License

MIT License. For educational and research purposes only.