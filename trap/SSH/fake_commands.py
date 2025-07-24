# fake_commands.py

def commands(cmd):
    responses = {
        "ls": "password.txt readme.md secret/",
        "ls -la": "drwxr-xr-x 2 user user 4096 Jul 23 12:00 secret/",
        "pwd": "/home/user",
        "cd": "",
        "cat password.txt": "supersecretpassword",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash",
        "whoami": "user",
        "exit": "Bye!!",
        "history": "1  ls\n2  pwd\n3  whoami",
        "ps aux": "root      1  0.0  0.1  18520  3164 ? Ss   10:00   0:00 /sbin/init",
        "wget": "Downloading...",
        "curl": "Fetching data...",
        "nmap": "Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-23",
        "nc": "Listening on port...",
        "netstat": "Active Internet connections (servers and established)",
        "sudo": "Sorry, user user is not allowed to execute '/bin/bash' as root.",
        "passwd": "Changing password for user user.",
        "rm -rf": "Permission denied",
        "ssh-keygen": "Generating public/private rsa key pair...",
        "chmod 777": "",
        "scp": "copying file...",
        "ping": "PING google.com (8.8.8.8): 56 data bytes"
    }

    for pattern, response in responses.items():
        if cmd.startswith(pattern):
            return response
    return "Command not found"
