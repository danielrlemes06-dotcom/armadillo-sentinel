from pathlib import Path

import psycopg2
import pytest

from armadillo_sentinel.db import get_connection

TEST_SCHEMA = "sentinel_test"
SCHEMA_SQL = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"


def connect_test_schema():
    """Conexao isolada: so enxerga o schema de teste, nunca as tabelas reais."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(f"SET search_path TO {TEST_SCHEMA}")
    conn.commit()
    return conn


@pytest.fixture(scope="session")
def pg_schema():
    try:
        admin = get_connection()
    except psycopg2.OperationalError:
        pytest.skip("PostgreSQL indisponivel: testes de banco ignorados")
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {TEST_SCHEMA} CASCADE")
        cur.execute(f"CREATE SCHEMA {TEST_SCHEMA}")
        cur.execute(f"SET search_path TO {TEST_SCHEMA}")
        cur.execute(SCHEMA_SQL.read_text(encoding="utf-8"))
    yield
    with admin.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {TEST_SCHEMA} CASCADE")
    admin.close()


@pytest.fixture
def db(pg_schema, monkeypatch):
    # run_detectors abre a propria conexao: aponta para o schema de teste
    monkeypatch.setattr("armadillo_sentinel.detectors.get_connection", connect_test_schema)
    conn = connect_test_schema()
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("TRUNCATE log_events, alerts RESTART IDENTITY")
    yield conn
    conn.close()
