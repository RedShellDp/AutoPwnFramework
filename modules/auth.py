import json
import hashlib

USERS_DB = "users.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    try:
        with open(USERS_DB) as f:
            return json.load(f)
    except FileNotFoundError:
        print("[-] users.json file not found.")
        exit(1)
    except json.JSONDecodeError:
        print("[-] users.json is corrupted or has syntax errors.")
        exit(1)

def clean_input(text):
    return text.strip().replace('\u200b', '').replace('\ufeff', '').replace('\n', '').replace('\r', '')

def login():
    users = load_users()
    username = clean_input(input("👤 Username: "))
    password = clean_input(input("🔑 Password: "))

    hashed = hash_password(password)

    print(f"[DEBUG] Hashed input password: {hashed}")
    print(f"[DEBUG] Stored password: {users.get(username, {}).get('password')}")

    if username in users and users[username]["password"] == hashed:
        print(f"[+] Authenticated as {username} (role: {users[username]['role']})")
        return username, users[username]["role"]
    else:
        print("[-] Invalid credentials.")
        exit(1)

