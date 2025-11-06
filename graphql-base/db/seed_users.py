# graphql-base/db/seed_users.py
import os, bcrypt, psycopg2, json
from psycopg2.extras import execute_values

DSN = os.environ.get("PROJECT_DB_DSN", "postgresql://postgres:postgres@localhost:5432/graphql_base")

USERS = [
    {"id": "user-001", "username": "rino", "password": "testpass", "roles": ["admin"]},
    {"id": "user-002", "username": "alex", "password": "password", "roles": ["viewer"]}
]

def seed():
    conn = psycopg2.connect(DSN)
    try:
        with conn:
            with conn.cursor() as cur:
                rows = []
                for u in USERS:
                    h = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
                    rows.append((u["id"], u["username"], h, u["roles"]))
                execute_values(cur,
                    "INSERT INTO auth_users (id, username, hashed_password, roles) VALUES %s ON CONFLICT (username) DO UPDATE SET hashed_password = EXCLUDED.hashed_password, roles = EXCLUDED.roles, updated_at = NOW()",
                    rows
                )
                print("seeded users")
    finally:
        conn.close()

if __name__ == "__main__":
    seed()

