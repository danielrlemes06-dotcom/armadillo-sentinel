from datetime import datetime, timedelta

import pytest

from armadillo_sentinel.detectors import (
    detect_brute_force,
    detect_odd_hours,
    detect_suspicious_ips,
    run_detectors,
)

BASE = datetime(2026, 11, 21, 3, 0, 0)
ATTACKER = "203.0.113.50"


def failures(ip, n, step=5, start=BASE, users=("root",)):
    return [
        (start + timedelta(seconds=i * step), ip, "login_failed", users[i % len(users)])
        for i in range(n)
    ]


def insert(conn, rows):
    with conn.cursor() as cur:
        for ts, ip, kind, user in rows:
            cur.execute(
                "INSERT INTO log_events "
                "(event_time, source_ip, username, service, event_type, raw_line, source) "
                "VALUES (%s, %s, %s, 'sshd', %s, %s, 'test')",
                (ts, ip, user, kind, f"{ts.isoformat()} {ip} {kind} {user}"),
            )


def run(conn, detector):
    with conn.cursor() as cur:
        return detector(cur)


def alerts(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT alert_type, host(source_ip), severity FROM alerts ORDER BY id")
        return cur.fetchall()


# ---------- forca bruta ----------

@pytest.mark.parametrize("n, expected", [(9, 0), (10, 1)])
def test_brute_force_threshold(db, n, expected):
    insert(db, failures(ATTACKER, n))
    assert run(db, detect_brute_force) == expected
    assert len(alerts(db)) == expected


@pytest.mark.parametrize("n, severity", [(12, "medium"), (19, "medium"), (20, "high")])
def test_brute_force_severity(db, n, severity):
    insert(db, failures(ATTACKER, n))
    run(db, detect_brute_force)
    assert alerts(db) == [("brute_force", ATTACKER, severity)]


def test_brute_force_ignores_slow_attempts(db):
    insert(db, failures(ATTACKER, 12, step=600))
    assert run(db, detect_brute_force) == 0


def test_brute_force_counts_each_ip_separately(db):
    rows = failures("203.0.113.1", 6) + failures(
        "203.0.113.2", 6, start=BASE + timedelta(seconds=1)
    )
    insert(db, rows)
    assert run(db, detect_brute_force) == 0


def test_brute_force_ignores_successful_logins(db):
    rows = [
        (BASE + timedelta(seconds=i * 5), ATTACKER, "login_success", "maria")
        for i in range(15)
    ]
    insert(db, rows)
    assert run(db, detect_brute_force) == 0


# ---------- IP suspeito ----------

@pytest.mark.parametrize(
    "users, severity",
    [
        (("a",), "medium"),
        (("a", "b", "c"), "medium"),
        (("a", "b", "c", "d"), "high"),
    ],
)
def test_suspicious_ip_severity_by_distinct_users(db, users, severity):
    insert(db, failures(ATTACKER, 12, users=users))
    run(db, detect_suspicious_ips)
    assert alerts(db) == [("suspicious_ip", ATTACKER, severity)]


def test_suspicious_ip_catches_slow_scanner(db):
    insert(db, failures(ATTACKER, 12, step=600))
    assert run(db, detect_suspicious_ips) == 1


def test_suspicious_ip_ignored_if_it_ever_logged_in(db):
    rows = failures(ATTACKER, 12) + [
        (BASE + timedelta(hours=1), ATTACKER, "login_success", "maria")
    ]
    insert(db, rows)
    assert run(db, detect_suspicious_ips) == 0


def test_suspicious_ip_below_threshold(db):
    insert(db, failures(ATTACKER, 9))
    assert run(db, detect_suspicious_ips) == 0


# ---------- horario incomum ----------

@pytest.mark.parametrize(
    "hour, minute, expected",
    [(0, 0, 1), (2, 41, 1), (5, 59, 1), (6, 0, 0), (9, 0, 0),
     (21, 59, 0), (22, 0, 1), (23, 30, 1)],
)
def test_odd_hours_boundaries(db, hour, minute, expected):
    when = datetime(2026, 11, 22, hour, minute, 0)
    insert(db, [(when, "198.51.100.99", "login_success", "maria")])
    assert run(db, detect_odd_hours) == expected
    assert len(alerts(db)) == expected


def test_odd_hours_ignores_failed_logins(db):
    insert(db, [(datetime(2026, 11, 22, 3, 0, 0), ATTACKER, "login_failed", "root")])
    assert run(db, detect_odd_hours) == 0


def test_odd_hours_one_alert_per_ip(db):
    rows = [
        (datetime(2026, 11, 22, 2, m, 0), "198.51.100.99", "login_success", "maria")
        for m in (10, 20, 30)
    ]
    insert(db, rows)
    assert run(db, detect_odd_hours) == 1


# ---------- execucao completa ----------

def test_run_detectors_counts_and_is_idempotent(db):
    insert(db, failures(ATTACKER, 30, users=("a", "b", "c", "d")))
    insert(db, [(datetime(2026, 11, 22, 2, 41, 0), "198.51.100.99", "login_success", "maria")])
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO alerts (alert_type, source_ip, severity, description) "
            "VALUES ('manual', '198.51.100.1', 'low', 'criado a mao')"
        )

    expected = {"brute_force": 1, "suspicious_ip": 1, "odd_hour": 1}
    assert run_detectors() == expected
    assert run_detectors() == expected  # rodar de novo nao duplica alertas

    kinds = sorted(kind for kind, _ip, _sev in alerts(db))
    # alertas de outros tipos nao sao apagados
    assert kinds == ["brute_force", "manual", "odd_hour", "suspicious_ip"]


def test_honeypot_login_does_not_hide_suspicious_ip_nor_trigger_odd_hour(db):
    rows = failures(ATTACKER, 12) + [
        (datetime(2026, 11, 22, 3, 0, 0), ATTACKER, "honeypot_login", "root")
    ]
    insert(db, rows)
    assert run(db, detect_suspicious_ips) == 1
    assert run(db, detect_odd_hours) == 0
