#!/usr/bin/env python3
"""
LOLBins Detection Engine — Streamlit Dashboard
================================================
Interactive dashboard for visualizing detection results, exploring alerts,
and understanding why events were flagged.

Run with: streamlit run dashboard/app.py

Author: Eswar Achari
"""

import os
import sys

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Page configuration
st.set_page_config(
    page_title="LOLBins Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────── Data Loading ───────────

@st.cache_data
def load_data():
    """Load pipeline results."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(project_root, 'data', 'pipeline_results.csv')

    if not os.path.exists(data_path):
        st.error("⚠️ Pipeline results not found. Run the detection pipeline first:")
        st.code("python src/detection_pipeline.py", language="bash")
        st.stop()

    df = pd.read_csv(data_path)
    df['UtcTime'] = pd.to_datetime(df['UtcTime'], errors='coerce')

    # Extract process basenames for display
    df['child_process'] = df['Image'].apply(
        lambda x: os.path.basename(str(x)) if pd.notna(x) else 'unknown')
    df['parent_process'] = df['ParentImage'].apply(
        lambda x: os.path.basename(str(x)) if pd.notna(x) else 'unknown')

    return df


# ─────────── Custom CSS ───────────

st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        border: 1px solid #0f3460;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        color: #e94560;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #a0a0a0;
        margin-top: 5px;
    }
    .stDataFrame { font-size: 0.85rem; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
</style>
""", unsafe_allow_html=True)


# ─────────── Main App ───────────

def main():
    # Header
    st.title("🛡️ LOLBins Hybrid Detection Engine")
    st.markdown(
        "*Multi-layer detection combining Sigma rules, ML anomaly scoring, "
        "and behavioral chain analysis*"
    )
    st.markdown("---")

    # Load data
    df = load_data()

    # ═══════ Sidebar Filters ═══════
    st.sidebar.header("🔍 Filters")

    # Priority filter
    priorities = ['All'] + sorted(df['priority'].unique().tolist())
    selected_priority = st.sidebar.selectbox("Priority Level", priorities)

    # Verdict filter
    verdicts = ['All'] + sorted(df['final_verdict'].unique().tolist())
    selected_verdict = st.sidebar.selectbox("Verdict", verdicts)

    # Label filter
    labels = ['All'] + sorted(df['label'].unique().tolist())
    selected_label = st.sidebar.selectbox("Event Label", labels)

    # ML score range
    ml_range = st.sidebar.slider(
        "ML Anomaly Score Range",
        min_value=0.0, max_value=100.0,
        value=(0.0, 100.0), step=5.0
    )

    # Apply filters
    filtered = df.copy()
    if selected_priority != 'All':
        filtered = filtered[filtered['priority'] == selected_priority]
    if selected_verdict != 'All':
        filtered = filtered[filtered['final_verdict'] == selected_verdict]
    if selected_label != 'All':
        filtered = filtered[filtered['label'] == selected_label]
    filtered = filtered[
        (filtered['ml_anomaly_score'] >= ml_range[0]) &
        (filtered['ml_anomaly_score'] <= ml_range[1])
    ]

    # ═══════ Summary Metrics ═══════
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Events", f"{len(df):,}")
    with col2:
        total_alerts = len(df[df['final_verdict'] == 'ALERT'])
        st.metric("🚨 Alerts", f"{total_alerts}", delta=None)
    with col3:
        critical = len(df[df['priority'] == 'CRITICAL'])
        st.metric("🔴 Critical", f"{critical}")
    with col4:
        high = len(df[df['priority'] == 'HIGH'])
        st.metric("🟠 High", f"{high}")
    with col5:
        medium = len(df[df['priority'] == 'MEDIUM'])
        st.metric("🟡 Medium", f"{medium}")

    st.markdown("---")

    # ═══════ Visualizations ═══════
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview", "🚨 Alerts Table", "📈 Analytics", "🔬 Detail View"
    ])

    with tab1:
        col_left, col_right = st.columns(2)

        with col_left:
            # Priority distribution
            priority_counts = filtered['priority'].value_counts().reset_index()
            priority_counts.columns = ['Priority', 'Count']
            color_map = {
                'CRITICAL': '#e74c3c', 'HIGH': '#e67e22',
                'MEDIUM': '#f1c40f', 'LOW': '#3498db', 'NONE': '#2ecc71'
            }
            fig_priority = px.bar(
                priority_counts, x='Priority', y='Count',
                color='Priority', color_discrete_map=color_map,
                title="Alert Priority Distribution",
            )
            fig_priority.update_layout(
                template='plotly_dark', showlegend=False,
                height=350,
            )
            st.plotly_chart(fig_priority, use_container_width=True)

        with col_right:
            # ML score distribution by label
            fig_scores = px.histogram(
                filtered, x='ml_anomaly_score', color='label',
                nbins=40, title="ML Anomaly Score Distribution",
                color_discrete_map={
                    'benign': '#2ecc71', 'malicious': '#e74c3c',
                    'gray_area': '#f1c40f'
                },
                barmode='overlay', opacity=0.7,
            )
            fig_scores.add_vline(x=70, line_dash="dash", line_color="red",
                                annotation_text="Threshold=70")
            fig_scores.update_layout(template='plotly_dark', height=350)
            st.plotly_chart(fig_scores, use_container_width=True)

        # Detection layer comparison
        col_a, col_b = st.columns(2)
        with col_a:
            # Verdict breakdown
            verdict_counts = filtered['final_verdict'].value_counts().reset_index()
            verdict_counts.columns = ['Verdict', 'Count']
            fig_verdict = px.pie(
                verdict_counts, values='Count', names='Verdict',
                title="Final Verdict Distribution",
                color='Verdict',
                color_discrete_map={
                    'ALERT': '#e74c3c', 'REVIEW': '#f1c40f', 'CLEAR': '#2ecc71'
                },
                hole=0.4,
            )
            fig_verdict.update_layout(template='plotly_dark', height=350)
            st.plotly_chart(fig_verdict, use_container_width=True)

        with col_b:
            # Sigma rule match distribution
            if 'sigma_rule_name' in filtered.columns:
                sigma_matches = filtered[filtered['sigma_match'] == True]
                if len(sigma_matches) > 0:
                    rule_counts = sigma_matches['sigma_rule_name'].value_counts().reset_index()
                    rule_counts.columns = ['Rule', 'Count']
                    fig_rules = px.bar(
                        rule_counts, x='Count', y='Rule',
                        orientation='h', title="Sigma Rule Matches",
                        color='Count', color_continuous_scale='Reds',
                    )
                    fig_rules.update_layout(
                        template='plotly_dark', height=350,
                        yaxis={'categoryorder': 'total ascending'},
                    )
                    st.plotly_chart(fig_rules, use_container_width=True)
                else:
                    st.info("No Sigma rule matches in filtered data")

    with tab2:
        st.subheader("🚨 Detection Alerts")

        # Show alerts
        alerts = filtered[filtered['final_verdict'].isin(['ALERT', 'REVIEW'])]

        if len(alerts) > 0:
            # Display columns
            display_cols = [
                'UtcTime', 'priority', 'parent_process', 'child_process',
                'sigma_rule_name', 'ml_anomaly_score', 'chain_risk_score',
                'confidence', 'label',
            ]
            available_cols = [c for c in display_cols if c in alerts.columns]

            st.dataframe(
                alerts[available_cols].sort_values(
                    'confidence', ascending=False),
                use_container_width=True,
                height=500,
            )

            # Download button
            csv = alerts.to_csv(index=False)
            st.download_button(
                "📥 Download Alerts CSV",
                csv, "alerts_export.csv", "text/csv",
            )
        else:
            st.success("✅ No alerts match the current filters")

    with tab3:
        st.subheader("📈 Feature Analytics")

        col1, col2 = st.columns(2)

        with col1:
            # Hourly distribution
            if 'hour_of_day' in filtered.columns:
                fig_hour = px.histogram(
                    filtered, x='hour_of_day', color='label',
                    nbins=24, title="Event Distribution by Hour",
                    color_discrete_map={
                        'benign': '#2ecc71', 'malicious': '#e74c3c',
                        'gray_area': '#f1c40f'
                    },
                    barmode='group',
                )
                fig_hour.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_hour, use_container_width=True)

        with col2:
            # Entropy distribution
            if 'command_line_entropy' in filtered.columns:
                fig_entropy = px.box(
                    filtered, x='label', y='command_line_entropy',
                    color='label', title="Command Line Entropy by Label",
                    color_discrete_map={
                        'benign': '#2ecc71', 'malicious': '#e74c3c',
                        'gray_area': '#f1c40f'
                    },
                )
                fig_entropy.update_layout(template='plotly_dark', height=350)
                st.plotly_chart(fig_entropy, use_container_width=True)

        # MITRE ATT&CK coverage
        if 'mitre_technique_id' in filtered.columns:
            st.subheader("🎯 MITRE ATT&CK Technique Coverage")
            malicious = filtered[filtered['is_malicious'] == 1]
            if len(malicious) > 0:
                tech_data = []
                for tid in malicious['mitre_technique_id'].unique():
                    if not tid or pd.isna(tid):
                        continue
                    subset = malicious[malicious['mitre_technique_id'] == tid]
                    tname = subset['technique_name'].iloc[0] if 'technique_name' in subset.columns else ''
                    detected = subset['final_verdict'].isin(['ALERT', 'REVIEW']).sum()
                    total = len(subset)
                    tech_data.append({
                        'Technique': f"{tid}: {tname}",
                        'Total': total,
                        'Detected': detected,
                        'Detection Rate': detected / max(total, 1) * 100,
                    })
                tech_df = pd.DataFrame(tech_data)
                if len(tech_df) > 0:
                    fig_tech = px.bar(
                        tech_df, x='Detection Rate', y='Technique',
                        orientation='h', title="Detection Rate by Technique",
                        color='Detection Rate',
                        color_continuous_scale='RdYlGn',
                        range_color=[0, 100],
                    )
                    fig_tech.update_layout(
                        template='plotly_dark', height=400,
                        yaxis={'categoryorder': 'total ascending'},
                    )
                    st.plotly_chart(fig_tech, use_container_width=True)

    with tab4:
        st.subheader("🔬 Event Detail View")
        st.markdown("Select an event to see its full feature breakdown and detection reasoning.")

        # Event selector
        event_idx = st.number_input(
            "Event Index", min_value=0,
            max_value=len(filtered)-1 if len(filtered) > 0 else 0,
            value=0, step=1,
        )

        if len(filtered) > 0 and event_idx < len(filtered):
            event = filtered.iloc[event_idx]

            col_info, col_detect = st.columns(2)

            with col_info:
                st.markdown("### 📋 Event Information")
                st.markdown(f"**Timestamp:** {event.get('UtcTime', 'N/A')}")
                st.markdown(f"**Process:** {event.get('child_process', 'N/A')}")
                st.markdown(f"**Parent:** {event.get('parent_process', 'N/A')}")
                st.markdown(f"**User:** {event.get('User', 'N/A')}")
                st.markdown(f"**Integrity:** {event.get('IntegrityLevel', 'N/A')}")

                cmd = str(event.get('CommandLine', ''))[:200]
                st.markdown(f"**Command Line:**")
                st.code(cmd, language="powershell")

            with col_detect:
                st.markdown("### 🎯 Detection Results")

                verdict = event.get('final_verdict', 'N/A')
                priority = event.get('priority', 'N/A')
                color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                         'LOW': '🔵', 'NONE': '🟢'}.get(priority, '⚪')

                st.markdown(f"**Verdict:** {verdict} {color} {priority}")
                st.markdown(f"**Confidence:** {event.get('confidence', 0):.1f}%")
                st.markdown(f"**Sigma Match:** {event.get('sigma_rule_name', 'None')}")
                st.markdown(f"**ML Score:** {event.get('ml_anomaly_score', 0):.1f}/100")
                st.markdown(f"**Chain Risk:** {event.get('chain_risk_score', 0):.0f}/100")

                # Explanation
                explanation = event.get('explanation', '')
                if explanation:
                    st.markdown("**Why flagged:**")
                    st.info(explanation)

            # Feature breakdown
            st.markdown("### 📊 Feature Values")
            feature_cols = [
                'is_known_lolbin', 'is_scripting_engine',
                'command_line_length', 'command_line_entropy',
                'has_suspicious_flag', 'contains_url',
                'has_base64_pattern', 'has_encoded_command',
                'has_download_indicator', 'process_ancestry_depth',
                'parent_is_office_app', 'is_off_hours',
                'parent_child_pair_rarity', 'command_length_zscore',
                'entropy_zscore',
            ]
            available_features = [c for c in feature_cols if c in event.index]
            if available_features:
                feature_data = {col: [event[col]] for col in available_features}
                st.dataframe(pd.DataFrame(feature_data).T.rename(
                    columns={0: 'Value'}), use_container_width=True)


    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        "LOLBins Hybrid Detection Engine | Built by Eswar Achari | "
        "Powered by Sigma Rules + Isolation Forest + LOF + One-Class SVM"
        "</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
