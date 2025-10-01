import os
import json

# Resolve path to users.json
USER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "db", "users.json"))

# Load user store
with open(USER_PATH) as f:
    users = json.load(f)

def get_user(username: str):
    user = users.get(username)
    print(f"[user.py] Lookup for '{username}': {'FOUND' if user else 'NOT FOUND'}")
    return user
