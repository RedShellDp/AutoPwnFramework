import os
from datetime import datetime

log_dir = "logs"
log_file = os.path.join(log_dir, "audit.log")
os.makedirs(log_dir, exist_ok=True)

def log_action(username, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {username}: {action}\n"
    with open(log_file, "a") as f:
        f.write(entry)
