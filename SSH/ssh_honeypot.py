import sys
import os
import socket
import threading
from colorama import Fore, Style

# Add parent directories to import local modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from dataBase.mongo_client import log_attack
from fake_commands import commands
from utils import calculate_criticality, classify_risk

# Configuration
HOST = "0.0.0.0"
PORT = 2222
BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\n"

def handle_client(client_socket, addr):
    ip = addr[0]
    print(Fore.YELLOW + f"[!] Connection from {ip}" + Style.RESET_ALL)

    try:
        client_socket.sendall(BANNER)

        # Get Username
        client_socket.sendall(b"Username: ")
        username = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()

        # Get Password
        client_socket.sendall(b"Password: ")
        password = client_socket.recv(1024).decode("utf-8", errors="ignore").strip()

        # Log login event
        log_attack("login", {
            "ip": ip,
            "username": username,
            "password": password
        })

        # Fake welcome message
        client_socket.sendall(b"\nWelcome to Ubuntu 20.04 LTS\n")
        prompt = f"{username}@fakehost:~$ ".encode()
        client_socket.sendall(prompt)

        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            cmd = data.decode("utf-8", errors="ignore").strip()
            if cmd == "":
                continue

            # Log command execution attempt
            criticality = calculate_criticality(cmd)
            score = classify_risk(criticality)
            log_attack("command", {
                "ip": ip,
                "username": username,
                "command": cmd,
                "criticality": criticality,
                "score": score
            })

            # Respond with fake output
            response = commands(cmd)
            client_socket.sendall(response.encode("utf-8") + b"\n")
            client_socket.sendall(prompt)

    except Exception as e:
        print(Fore.RED + f"[X] Error: {e}" + Style.RESET_ALL)
    finally:
        client_socket.close()

def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
        print(Fore.GREEN + f"[+] SSH Honeypot Listening on port {PORT}..." + Style.RESET_ALL)

        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            thread.start()
    except Exception as e:
        print(Fore.RED + f"[X] Server Error: {e}" + Style.RESET_ALL)
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
