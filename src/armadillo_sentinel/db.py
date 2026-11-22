import os

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()

COLUMNS = (
    "event_time", "source_ip", "username", "service",
    "event_type", "raw_line", "source",
)


def get_connection():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "sentinel"),
        user=os.getenv("POSTGRES_USER", "sentinel"),
        password=os.getenv("POSTGRES_PASSWORD"),
    )


def insert_events(events):
    if not events:
        return 0
    rows = [tuple(e[c] for c in COLUMNS) for e in events]
    sql = f"INSERT INTO log_events ({', '.join(COLUMNS)}) VALUES %s"
    with get_connection() as conn, conn.cursor() as cur:
        execute_values(cur, sql, rows)
    return len(rows)
