# 🛡️ SSH & Web Honeypot System with Real-Time Admin Dashboard

A secure, Python-based honeypot system that simulates an SSH server and a fake Linux web login page to lure attackers and capture their behavior. All logs are stored in MongoDB and visualized via a React-based Admin Dashboard with dynamic criticality scoring.

---

## 📦 Features

- ⚠️ **SSH Honeypot**
  - Listens on a specified port
  - Captures IP, username, password, and command attempts
  - Detects scans (Nmap, etc.)
  - Simulates a fake Linux file system
  - Dynamically assigns **criticality scores**

- 🕵️ **Fake Login Web Page**
  - React-based simple login form (port 5173)
  - Logs credentials entered (username + password)
  - Sends logs to backend Flask API

- 📊 **Admin Dashboard**
  - Built with React and Tailwind
  - Displays attacker IPs, locations (GeoIP), command history
  - Visualizes critical scores over time
  - Filter/search/sort logs

- ☁️ **Backend**
  - Python Flask API
  - Stores data in MongoDB
  - Handles REST endpoints from SSH and web honeypots

---

## 🛠️ Tech Stack

| Part              | Tech                          |
|-------------------|-------------------------------|
| SSH Honeypot      | Python, Socket, Paramiko      |
| Web Fake Login    | React, Fetch API              |
| Backend API       | Flask, MongoDB (PyMongo)      |
| Admin Dashboard   | React, Tailwind, Chart.js     |
| Logging & Scoring | Custom Criticality Engine     |

---