import pandas as pd
import streamlit as st

from armadillo_sentinel.db import get_connection
from armadillo_sentinel.reports import build_reports, fetch_df

st.set_page_config(page_title="Armadillo Sentinel", layout="wide")

ALERTS_SQL = """
    SELECT severity AS severidade, alert_type AS tipo, host(source_ip) AS ip,
           description AS descricao, created_at AS criado_em
    FROM alerts
    ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id
"""


@st.cache_data(ttl=30)
def load_data():
    reports = build_reports()
    with get_connection() as conn, conn.cursor() as cur:
        alerts = fetch_df(cur, ALERTS_SQL)
    return reports, alerts


def ranking(df):
    if df.empty:
        st.write("Sem dados.")
        return
    st.dataframe(
        df,
        hide_index=True,
        column_config={
            "falhas": st.column_config.ProgressColumn(
                "falhas", min_value=0, max_value=int(df["falhas"].max()), format="%d"
            )
        },
    )


st.title("Armadillo Sentinel")
st.caption("Painel de análise de logs de autenticação")

if st.button("Atualizar dados"):
    st.cache_data.clear()

try:
    reports, alerts = load_data()
except Exception as exc:
    st.error(f"Não foi possível ler o banco: {exc}")
    st.stop()

resumo = reports["resumo"].iloc[0]
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Eventos", int(resumo["eventos"]))
c2.metric("Falhas de login", int(resumo["falhas"]))
c3.metric("Logins bem-sucedidos", int(resumo["sucessos"]))
c4.metric("IPs distintos", int(resumo["ips_distintos"]))
c5.metric("Alertas", len(alerts))

if pd.notna(resumo["primeiro_evento"]):
    st.caption(
        f"Período analisado: {resumo['primeiro_evento']:%d/%m/%Y %H:%M} "
        f"a {resumo['ultimo_evento']:%d/%m/%Y %H:%M} (UTC)"
    )

st.subheader("Alertas")
if alerts.empty:
    st.info("Nenhum alerta. Rode 'sentinel detect' para gerá-los.")
else:
    st.dataframe(alerts, hide_index=True)

left, right = st.columns(2)
with left:
    st.subheader("Falhas por hora do dia")
    st.bar_chart(reports["falhas_por_hora"].set_index("hora")["falhas"])
with right:
    st.subheader("Eventos por dia")
    st.bar_chart(reports["eventos_por_dia"].astype({"dia": str}).set_index("dia")[["falhas", "sucessos"]])

left, right = st.columns(2)
with left:
    st.subheader("IPs com mais falhas")
    ranking(reports["top_ips_falhas"])
with right:
    st.subheader("Usuários mais visados")
    ranking(reports["usuarios_mais_visados"])

