from .db import get_connection


def detect_brute_force(cur):
    sql = """
        WITH attempts AS (
            SELECT
                source_ip,
                event_time,
                COUNT(*) OVER (
                    PARTITION BY source_ip
                    ORDER BY event_time
                    RANGE BETWEEN INTERVAL '5 minutes' PRECEDING
                    AND CURRENT ROW
                ) AS failures
            FROM log_events
            WHERE event_type = 'login_failed'
              AND source_ip IS NOT NULL
        )
        SELECT source_ip, MAX(failures)
        FROM attempts
        GROUP BY source_ip
        HAVING MAX(failures) >= 10;
    """

    cur.execute(sql)
    results = cur.fetchall()

    for ip, failures in results:
        severity = "high" if failures >= 20 else "medium"
        description = (
            f"{failures} tentativas de login em uma janela de "
            f"5 minutos. Possível ataque de força bruta."
        )
        cur.execute(
            """
            INSERT INTO alerts (alert_type, source_ip, severity, description)
            VALUES (%s, %s, %s, %s)
            """,
            ("brute_force", ip, severity, description),
        )

    return len(results)


def detect_suspicious_ips(cur):
    sql = """
        SELECT
            source_ip,
            COUNT(*) AS failures,
            COUNT(DISTINCT username) AS usernames
        FROM log_events
        WHERE event_type = 'login_failed'
          AND source_ip IS NOT NULL
        GROUP BY source_ip
        HAVING COUNT(*) >= 10
           AND NOT EXISTS (
               SELECT 1
               FROM log_events success
               WHERE success.source_ip = log_events.source_ip
                 AND success.event_type = 'login_success'
           );
    """

    cur.execute(sql)
    results = cur.fetchall()

    for ip, failures, usernames in results:
        severity = "high" if usernames >= 4 else "medium"
        description = (
            f"{failures} falhas de login, tentando acessar "
            f"{usernames} nomes de usuário diferentes, sem login bem-sucedido."
        )
        cur.execute(
            """
            INSERT INTO alerts (alert_type, source_ip, severity, description)
            VALUES (%s, %s, %s, %s)
            """,
            ("suspicious_ip", ip, severity, description),
        )

    return len(results)


def detect_odd_hours(cur):
    sql = """
        SELECT
            source_ip,
            COUNT(*) AS successes
        FROM log_events
        WHERE event_type = 'login_success'
          AND source_ip IS NOT NULL
          AND (
              EXTRACT(HOUR FROM event_time) < 6
              OR EXTRACT(HOUR FROM event_time) >= 22
          )
        GROUP BY source_ip;
    """

    cur.execute(sql)
    results = cur.fetchall()

    for ip, successes in results:
        description = (
            f"{successes} login(s) bem-sucedido(s) "
            f"em horário incomum (entre 22h e 6h)."
        )
        cur.execute(
            """
            INSERT INTO alerts (alert_type, source_ip, severity, description)
            VALUES (%s, %s, %s, %s)
            """,
            ("odd_hour", ip, "medium", description),
        )

    return len(results)


def run_detectors():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM alerts
                WHERE alert_type IN (
                    'brute_force',
                    'suspicious_ip',
                    'odd_hour'
                );
            """)

            brute = detect_brute_force(cur)
            suspicious = detect_suspicious_ips(cur)
            odd = detect_odd_hours(cur)

    return {
        "brute_force": brute,
        "suspicious_ip": suspicious,
        "odd_hour": odd,
    }


def list_alerts():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT alert_type, source_ip, severity, description, created_at
                FROM alerts
                ORDER BY
                    CASE severity
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    created_at DESC
                LIMIT 50;
            """)
            return cur.fetchall()
