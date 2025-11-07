# tice_app_ui.py — RICE Threat Intelligence (aligned button + compact charts)

import streamlit as st
import pandas as pd
import sys
import os
import json
import re
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go

# --- Ensure local imports work ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from tice_api_collector import get_raw_threat_data, process_raw_data, is_valid_ip
except ImportError as e:
    st.set_page_config(page_title="RICE Threat Intelligence", layout="wide")
    st.error(f"❌ Error: Could not import core logic from 'tice_api_collector.py'. Details: {e}")
    st.stop()

# --- Page Config ---
st.set_page_config(page_title="🛡️ RICE Threat Intelligence", layout="wide", initial_sidebar_state="expanded")

# --- CSS (theme, cards, aligned button, compact charts) ---
st.markdown("""
<style>
:root { --bg:#0f172a; --panel:#111827; --card:#0b1220; --text:#e5e7eb; --muted:#9ca3af; --accent:#22d3ee; --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; }
html, body, [data-testid="stAppViewContainer"] { background: linear-gradient(180deg,#0b1220 0%,#0f172a 60%,#0f172a 100%) !important; color: var(--text); }
h1, h2, h3, h4 { color: var(--text) !important; }

.input-panel {
  background:#0c1426; border:1px solid #1f2937; padding:12px 14px;
  border-radius:14px; box-shadow:0 10px 30px rgba(0,0,0,.35);
  display:flex; align-items:center; gap:12px;
}
.input-panel .field { flex:1; }
.input-panel .btn { flex:0 0 150px; }

.card {
  background:var(--card); border:1px solid #1e293b; border-radius:16px;
  padding:18px 18px 14px; box-shadow:0 10px 30px rgba(0,0,0,.35);
}

.metric-title { font-size:.85rem; color:var(--muted); margin-bottom:.25rem; }
.metric-value { font-size:1.75rem; font-weight:700; }

.badge {
  display:inline-flex; align-items:center; gap:.5rem; font-weight:600;
  padding:.35rem .75rem; border-radius:999px; border:1px solid #1f2937; background:#0c1426;
}
.badge.bad{color:#fecaca;background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.35);}
.badge.warn{color:#fde68a;background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.35);}
.badge.ok{color:#bbf7d0;background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.35);}

.rail {
  height:10px; width:100%;
  background:linear-gradient(90deg,#16a34a 0 33%,#f59e0b 33% 66%,#ef4444 66% 100%);
  border-radius:999px; opacity:.25; margin-top:.35rem;
}
.progress { height:10px; border-radius:999px; margin-top:-10px; background:linear-gradient(90deg,var(--accent),#3b82f6); }

button[kind="secondary"], button[kind="primary"]{
  height:3rem!important; font-weight:600; border-radius:10px!important;
  background:linear-gradient(90deg,#22d3ee 0%,#3b82f6 100%)!important; color:white!important; border:none!important; transition:.2s all;
}
button[kind="secondary"]:hover, button[kind="primary"]:hover{ transform:translateY(-1px); box-shadow:0 4px 14px rgba(34,211,238,.4); }
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ Threat Intelligence Correlation Engine")
st.caption("AI-Driven Multi-Source Threat Analysis & Attribution")

# --- Input Panel (Aligned) ---
st.markdown('<div class="input-panel">', unsafe_allow_html=True)
st.markdown('<div class="field">', unsafe_allow_html=True)
ip_address = st.text_input("IP Address Lookup", value="8.8.8.8", max_chars=20,
                           label_visibility="collapsed", placeholder="Enter an IPv4 address (e.g., 1.1.1.1)")
st.markdown('</div>', unsafe_allow_html=True)
st.markdown('<div class="btn">', unsafe_allow_html=True)
go_btn = st.button("🔍 Analyze", use_container_width=True)
st.markdown('</div></div>', unsafe_allow_html=True)

# --- Helpers ---
def status_badge(score_int: int) -> str:
    if score_int >= 80: return '<span class="badge bad">Malicious</span>'
    if score_int >= 40: return '<span class="badge warn">Suspicious</span>'
    return '<span class="badge ok">Benign</span>'

def build_threat_df(final_report: dict) -> pd.DataFrame:
    """
    Build DataFrame for donut that always returns rows.
    Priority:
      1) Specific types (non AIP/VT summary)
      2) Parse counts from 'AbuseIPDB Reports (168)', 'VirusTotal Malicious Hits (3)'
      3) Fallback slice when nothing exists
    """
    cats = final_report.get("categories", []) or []
    specific = [c for c in cats if not c.startswith("AbuseIPDB Reports") and not c.startswith("VirusTotal Malicious Hits")]
    if specific:
        counts = Counter(specific)
        return pd.DataFrame(counts.items(), columns=["Threat Type", "Count"])

    parsed = []
    for c in cats:
        m = re.search(r"\((\d+)\)", c)
        count = int(m.group(1)) if m else 0
        name = re.sub(r"\s*\(\d+\)\s*", "", c).strip()
        if name and count > 0:
            parsed.append((name, count))
    if parsed:
        return pd.DataFrame(parsed, columns=["Threat Type", "Count"])

    label = "No Reports / Benign" if final_report.get("severity_score", 0) == 0 else "Unspecified Signals"
    return pd.DataFrame([(label, 1)], columns=["Threat Type", "Count"])

# --- Main flow ---
if go_btn:
    ip_address_cleaned = ip_address.strip().rstrip('.')
    if not is_valid_ip(ip_address_cleaned):
        st.error(f"❌ '{ip_address}' is not a valid IPv4 address.")
        st.stop()

    with st.spinner(f"Collecting and analyzing data for **{ip_address_cleaned}**..."):
        raw_results = get_raw_threat_data(ip_address_cleaned)
        try:
            final_report = process_raw_data(ip_address_cleaned, raw_results)
        except Exception as e:
            st.error(f"❌ Critical error during data processing: {e}")
            st.caption("Raw results dump for debugging:")
            st.json(raw_results); st.stop()

    # JSON download
    report_json_string = json.dumps(final_report, indent=2)

    # --- IP header card ---
    st.markdown('<div class="card">', unsafe_allow_html=True)
    hc1, hc2 = st.columns([5,1.2])
    with hc1:
        st.subheader(final_report.get('ip_address', ip_address_cleaned))
        st.caption(f"Last scan: {pd.Timestamp('now').strftime('%d/%m/%Y, %H:%M:%S')}")
    with hc2:
        st.markdown(status_badge(int(final_report.get('severity_score', 0))), unsafe_allow_html=True)
    st.download_button("💾 Create and Download Full Analysis Report (JSON)",
                       data=report_json_string,
                       file_name=f"RICE_Threat_Report_{final_report['ip_address']}_{pd.Timestamp('now').strftime('%Y%m%d_%H%M%S')}.json",
                       mime="application/json", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")

    # --- Metrics row ---
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-title">Reputation</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{final_report["reputation"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-title">Confidence Score</div>', unsafe_allow_html=True)
        conf_pct = float(final_report.get("confidence_score", 0)) * 100.0
        st.markdown(f'<div class="metric-value">{conf_pct:.0f}%</div>', unsafe_allow_html=True)
        st.markdown('<div class="rail"></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="progress" style="width:{conf_pct:.0f}%"></div>', unsafe_allow_html=True)
        st.caption("Reliability of threat attribution")
        st.markdown('</div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-title">Severity Score</div>', unsafe_allow_html=True)
        sev_pct = float(final_report.get("severity_score", 0))
        st.markdown(f'<div class="metric-value">{int(sev_pct)}/100</div>', unsafe_allow_html=True)
        st.markdown('<div class="rail"></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="progress" style="width:{sev_pct:.0f}%"></div>', unsafe_allow_html=True)
        st.caption("Potential risk level")
        st.markdown('</div>', unsafe_allow_html=True)
    with c4:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="metric-title">Overall Status</div>', unsafe_allow_html=True)
        st.markdown(status_badge(int(sev_pct)), unsafe_allow_html=True)
        st.caption(final_report.get("summary", ""))
        st.markdown('</div>', unsafe_allow_html=True)

    st.write("")

    # --- Charts row (compact & aligned) ---
    ch1, ch2 = st.columns(2)

    # Threat Distribution — donut (compact)
    with ch1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("#### Threat Distribution")
        df_cat = build_threat_df(final_report)
        fig = px.pie(df_cat, values="Count", names="Threat Type", hole=0.45, title=None)
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font_color="#e5e7eb", margin=dict(l=0, r=0, t=20, b=10),
            legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5),
            height=320
        )
        fig.update_traces(textposition="inside", textinfo="percent+label", insidetextorientation="radial")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        st.caption("Shows specific threat types or summarized report counts; for benign IPs, 'No Reports / Benign'.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Score Analysis — bars (compact)
    with ch2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("#### Score Analysis")
        fig2 = go.Figure()
        fig2.add_bar(x=["Confidence", "Severity"], y=[conf_pct, sev_pct], width=[0.4, 0.4])
        fig2.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font_color="#e5e7eb", margin=dict(l=0, r=0, t=20, b=10),
            yaxis=dict(range=[0, 100], showgrid=False),
            xaxis=dict(showgrid=False),
            height=320
        )
        fig2.update_traces(marker_line_width=0, hovertemplate="%{x}: %{y}%")
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        st.caption(f"Confidence: **{conf_pct:.0f}%** · Severity: **{sev_pct:.0f}%**")
        st.markdown('</div>', unsafe_allow_html=True)

    st.write("")

    # --- Geolocation & Network cards ---
    g1, g2 = st.columns(2)
    geo = final_report.get('geolocation', {})

    with g1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("### 📍 Geolocation Data")
        st.markdown(f"**Location:** {geo.get('city','N/A')}, {geo.get('region','N/A')} — {geo.get('country','N/A')}")
        st.markdown(f"**Coordinates:** {geo.get('lat','N/A')}, {geo.get('lon','N/A')}")
        st.markdown(f"**Timezone:** {geo.get('timezone','N/A')}")
        hostnames = ", ".join(geo.get('hostnames', []) or ["N/A"])
        st.markdown(f"**Hostnames:** {hostnames}")
        st.caption("Geographic risk assessment considers patterns tied to known malicious infrastructure.")
        st.markdown('</div>', unsafe_allow_html=True)

    with g2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("### 🧬 Network Information")
        st.markdown(f"**ASN:** {geo.get('asn', 'N/A')}")
        st.markdown(f"**Organization:** {geo.get('org', 'N/A')}")
        st.markdown(f"**ISP:** {geo.get('isp', 'N/A')}")
        st.markdown(f"**Domains:** {', '.join(geo.get('domains', []) or ['N/A'])}")
        st.markdown('</div>', unsafe_allow_html=True)

    st.write("")

    # --- Threat Categories chips ---
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### ⚠️ Threat Categories")
    cats = final_report.get('categories', [])
    if cats:
        chips = " ".join([f'<span class="badge warn" style="margin-right:.5rem;margin-bottom:.5rem;">{c}</span>' for c in cats])
        st.markdown(chips, unsafe_allow_html=True)
        st.caption(f"Report Count: {final_report.get('report_count', '—')}")
    else:
        st.success("No specific threat categories found.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.write("")

    # --- Raw API responses (forensics) ---
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("### 🔗 Raw API Responses (Forensics)")
    if final_report.get('raw_api_results'):
        st.json(final_report['raw_api_results'])
    else:
        st.info("No raw data available.")
    st.markdown('</div>', unsafe_allow_html=True)
