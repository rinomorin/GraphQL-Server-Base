import json
from pathlib import Path
from datetime import datetime, timezone

LOG_DIR = Path("/opt/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

REVOKED_FILE = LOG_DIR / "revoked_tokens.json"

def write_log(entry: dict, stream: str = "default"):
    date_suffix = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{stream}.log.{date_suffix}.json"
    filepath = LOG_DIR / filename

    try:
        with open(filepath, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[logger] Failed to write log: {e}")

def is_revoked(token: str) -> bool:
    if not REVOKED_FILE.exists():
        return False

    try:
        with open(REVOKED_FILE, "r") as f:
            revoked = json.load(f)
        return token in revoked
    except Exception:
        return False

def revoke_token(token: str):
    revoked = []
    if REVOKED_FILE.exists():
        try:
            with open(REVOKED_FILE, "r") as f:
                revoked = json.load(f)
        except Exception:
            revoked = []

    if token not in revoked:
        revoked.append(token)

    try:
        with open(REVOKED_FILE, "w") as f:
            json.dump(revoked, f)
    except Exception as e:
        print(f"[logger] Failed to revoke token: {e}")

def log_ttl_expiry(user_id: str, role: str, trace_id: str, expires_at: datetime, token_type: str = "access"):
    entry = {
        "event": "ttl_expiry_scheduled",
        "user_id": user_id,
        "role": role,
        "trace_id": trace_id,
        "token_type": token_type,
        "expires_at": expires_at.isoformat(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    write_log(entry, stream=role)
