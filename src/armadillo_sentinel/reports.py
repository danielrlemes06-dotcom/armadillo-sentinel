import argparse
from pathlib import Path

import pandas as pd

from .db import get_connection

QUERIES = {
    "resumo": """
        SELECT count(*) AS eventos,
               count(*) FILTER (WHERE event_type = 'login_failed') AS falhas,
               count(*) FILTER (WHERE event_type = 'login_success') AS sucessos,
               count(DISTINCT source_ip) AS ips_distintos,
               min(event_time) AS primeiro_evento,
               max(event_time) AS ultimo_evento
        FROM log_events
    """,
    "top_ips_falhas": """
        SELECT host(source_ip) AS ip,
               count(*) AS falhas,
               count(DISTINCT username) AS usuarios_testados,
               min(event_time) AS primeira,
               max(event_time) AS ultima
        FROM log_events
        WHERE event_type = 'login_failed'
        GROUP BY source_ip
        ORDER BY falhas DESC
        LIMIT 10
    """,
    "usuarios_mais_visados": """
        SELECT username AS usuario,
               count(*) AS falhas,
               count(DISTINCT source_ip) AS ips_distintos
        FROM log_events
        WHERE event_type = 'login_failed'
        GROUP BY username
        ORDER BY falhas DESC
        LIMIT 10
    """,
    "falhas_por_hora": """
        SELECT EXTRACT(HOUR FROM event_time)::int AS hora,
               count(*) AS falhas
        FROM log_events
        WHERE event_type = 'login_failed'
        GROUP BY 1
        ORDER BY 1
    """,
    "eventos_por_dia": """
        SELECT event_time::date AS dia,
               count(*) FILTER (WHERE event_type = 'login_failed') AS falhas,
               count(*) FILTER (WHERE event_type = 'login_success') AS sucessos
        FROM log_events
        GROUP BY 1
        ORDER BY 1
    """,
    "alertas": """
        SELECT severity AS severidade, alert_type AS tipo, count(*) AS quantidade
        FROM alerts
        GROUP BY 1, 2
        ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, 2
    """,
}

TITLES = {
    "resumo": "RESUMO GERAL",
    "top_ips_falhas": "TOP 10 IPs COM MAIS FALHAS DE LOGIN",
    "usuarios_mais_visados": "USUARIOS MAIS VISADOS",
    "falhas_por_hora": "FALHAS POR HORA DO DIA",
    "eventos_por_dia": "EVENTOS POR DIA",
    "alertas": "ALERTAS POR SEVERIDADE E TIPO",
}


def fetch_df(cur, sql):
    cur.execute(sql)
    return pd.DataFrame(cur.fetchall(), columns=[d[0] for d in cur.description])


def build_reports():
    reports = {}
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SET TIME ZONE 'UTC'")
        for name, sql in QUERIES.items():
            reports[name] = fetch_df(cur, sql)

    # mostra as 24 horas, mesmo as sem falhas, com uma barra simples
    hours = reports["falhas_por_hora"].set_index("hora")
    hours = hours.reindex(range(24), fill_value=0).rename_axis("hora").reset_index()
    peak = max(int(hours["falhas"].max()), 1)
    hours["grafico"] = hours["falhas"].apply(lambda n: "#" * round(30 * n / peak))
    reports["falhas_por_hora"] = hours
    return reports


def main():
    ap = argparse.ArgumentParser(prog="python -m armadillo_sentinel.reports")
    ap.add_argument("--csv", action="store_true", help="exporta os relatorios para a pasta reports/")
    args = ap.parse_args()

    reports = build_reports()
    for name, df in reports.items():
        print(f"\n=== {TITLES[name]} ===")
        print(df.to_string(index=False) if not df.empty else "(sem dados)")

    if args.csv:
        out = Path("reports")
        out.mkdir(exist_ok=True)
        for name, df in reports.items():
            df.to_csv(out / f"{name}.csv", index=False)
        print(f"\nCSVs salvos em {out}/")


if __name__ == "__main__":
    main()
