# graphql-base/db/run_migrations.py
import os, glob, psycopg2

DSN = os.environ.get("PROJECT_DB_DSN", "postgresql://postgres:postgres@localhost:5432/graphql_base")
MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations")

def run():
    conn = psycopg2.connect(DSN)
    try:
        with conn:
            with conn.cursor() as cur:
                for path in sorted(glob.glob(os.path.join(MIGRATIONS_DIR, "*.sql"))):
                    with open(path, "r", encoding="utf-8") as f:
                        sql = f.read()
                        cur.execute(sql)
                        print("applied:", path)
    finally:
        conn.close()

if __name__ == "__main__":
    run()
