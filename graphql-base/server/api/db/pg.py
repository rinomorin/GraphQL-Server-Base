# graphql-base/server/api/db/pg.py
import os
import psycopg2
from psycopg2.extras import RealDictCursor

DB_DSN = os.environ.get("PROJECT_DB_DSN", "postgresql://postgres:postgres@localhost:5432/graphql_base")

def get_conn():
    return psycopg2.connect(DB_DSN)

def fetch_user_by_username(username: str):
    conn = None
    try:
        conn = get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, username, hashed_password, roles FROM auth_users WHERE username = %s", (username,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        if conn:
            conn.close()
