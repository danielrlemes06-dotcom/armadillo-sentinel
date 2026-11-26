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
    # timezone fixo em UTC: o horario gravado e o mesmo horario lido
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "sentinel"),
        user=os.getenv("POSTGRES_USER", "sentinel"),
        password=os.getenv("POSTGRES_PASSWORD"),
        options="-c timezone=UTC",
    )


def insert_events(events):
    """Insere eventos ignorando duplicados. Retorna quantos eram novos."""
    if not events:
        return 0
    rows = [tuple(e[c] for c in COLUMNS) for e in events]
    sql = (
        f"INSERT INTO log_events ({', '.join(COLUMNS)}) VALUES %s "
        "ON CONFLICT DO NOTHING RETURNING 1"
    )
    with get_connection() as conn, conn.cursor() as cur:
        inserted = execute_values(cur, sql, rows, fetch=True)
    return len(inserted)
