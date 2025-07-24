# utils.py

def calculate_criticality(command):
    scoring_rules = {
        "rm -rf": 10,
        "cat /etc/passwd": 8,
        "cat password.txt": 7,
        "nmap": 6,
        "netcat": 6,
        "nc": 6,
        "wget": 5,
        "curl": 5,
        "scp": 4,
        "ssh-keygen": 4,
        "ls -la": 3,
        "chmod 777": 5,
        "ps aux": 4,
        "netstat": 4,
        "ping": 2,
        "cd /": 3,
        "sudo": 7,
        "whoami": 2,
        "history": 3,
        "passwd": 6,
        "exit": 1
    }

    score = 0
    for pattern, value in scoring_rules.items():
        if pattern in command:
            score += value

    return score


def classify_risk(score):
    if score >= 15:
        return "High"
    elif score >= 7:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"
