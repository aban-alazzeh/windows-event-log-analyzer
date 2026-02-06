from pathlib import Path
import tempfile
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime


from engine.analyze import analyze

st.set_page_config(page_title="Windows Log Analyzer", layout="wide")


st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .verdict-box {
        padding: 2rem;
        border-radius: 10px;
        text-align: center;
        font-size: 2rem;
        font-weight: bold;
        margin: 2rem 0;
    }
    .suspicious {
        background-color: #ffebee;
        color: #c62828;
        border: 3px solid #c62828;
    }
    .benign {
        background-color: #e8f5e9;
        color: #2e7d32;
        border: 3px solid #2e7d32;
    }
    .detector-card {
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        border: 2px solid #e0e0e0;
    }
    .triggered-yes {
        background-color: #fff3e0;
        border-color: #f57c00;
    }
    .triggered-no {
        background-color: #f5f5f5;
        border-color: #9e9e9e;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🔍 Windows Event Logs Analyzer</div>', unsafe_allow_html=True)
st.write("Upload three CSV exports from Event Viewer: **Security**, **System**, and **PowerShell (Operational)**.")

col1, col2, col3 = st.columns(3)
with col1:
    security_file = st.file_uploader("📁 Security CSV", type=["csv"])
with col2:
    system_file = st.file_uploader("📁 System CSV", type=["csv"])
with col3:
    powershell_file = st.file_uploader("📁 PowerShell CSV", type=["csv"])

run_btn = st.button("🚀 Analyze Logs", type="primary", disabled=not (security_file and system_file and powershell_file))

def _save_upload(uploaded, suffix: str) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded.getbuffer())
    tmp.close()
    return tmp.name

def create_timeline_plot(detector_data, detector_name):
    """Create a timeline plot showing flagged windows for a detector"""
    top_windows = detector_data.get("top_windows", [])
    
    if not top_windows:
        return None
    
    
    times = []
    probs = []
    colors = []
    
    for window in top_windows:
        time_str = window.get("time_window", "")
        prob = window.get("suspicious_prob", 0)
        times.append(time_str)
        probs.append(prob * 100)  # Convert to percentage
        colors.append('#d32f2f' if prob >= 0.65 else '#ff9800')
    
    # Create the plot
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=times,
        y=probs,
        marker=dict(
            color=colors,
            line=dict(color='#333', width=1)
        ),
        text=[f'{p:.1f}%' for p in probs],
        textposition='outside',
        hovertemplate='<b>Time:</b> %{x}<br><b>Probability:</b> %{y:.1f}%<extra></extra>'
    ))
    
    # Add threshold line
    fig.add_hline(y=65, line_dash="dash", line_color="red", 
                  annotation_text="Threshold (65%)", annotation_position="right")
    
    fig.update_layout(
        title=f"{detector_name} - Suspicious Activity Timeline",
        xaxis_title="Time Window",
        yaxis_title="Suspicious Probability (%)",
        yaxis_range=[0, 105],
        height=400,
        showlegend=False,
        plot_bgcolor='rgba(240,240,240,0.5)',
        hovermode='x unified'
    )
    
    return fig

if run_btn:
    with st.spinner('🔄 Analyzing logs...'):
        try:
            sec_path = _save_upload(security_file, "_security.csv")
            sys_path = _save_upload(system_file, "_system.csv")
            ps_path  = _save_upload(powershell_file, "_powershell.csv")

            result = analyze(sec_path, sys_path, ps_path)
            preds = result.get("predictions", {})
            verdict = preds.get("overall_verdict", "Unknown")

            # Display Verdict with styling
            verdict_class = "suspicious" if verdict == "Suspicious" else "benign"
            verdict_icon = "⚠️" if verdict == "Suspicious" else "✅"
            st.markdown(f'<div class="verdict-box {verdict_class}">{verdict_icon} {verdict}</div>', 
                       unsafe_allow_html=True)

            # CSV Summary (collapsed)
            with st.expander("📊 CSV Summary"):
                summary = result.get("csv_summary", {})
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Security Logs", summary.get("security_rows", 0))
                with col2:
                    st.metric("System Logs", summary.get("system_rows", 0))
                with col3:
                    st.metric("PowerShell Logs", summary.get("powershell_rows", 0))

            # Notes from rules overlay
            notes = preds.get("notes", [])
            if notes:
                st.info("ℹ️ **Analysis Notes:**\n- " + "\n- ".join(notes))

            # Detector Results
            st.markdown("---")
            st.subheader("🎯 Detection Results")
            
            detectors = {
                "brute_force": "🔐 Brute Force Attack",
                "powershell": "💻 PowerShell Suspicious Activity",
                "privilege_escalation": "🔓 Privilege Escalation",
                "service_installation": "⚙️ Service Installation"
            }

            for det_key, det_name in detectors.items():
                data = preds.get(det_key, {})
                triggered = data.get('triggered', False)
                num_flagged = data.get('num_flagged_windows_raw', 0)
                
                with st.expander(f"{det_name} {'🔴 TRIGGERED' if triggered else '🟢 Clear'}", 
                               expanded=triggered):
                    col1, col2 = st.columns([1, 3])
                    
                    with col1:
                        st.metric("Status", "🔴 Triggered" if triggered else "🟢 Clear")
                        st.metric("Flagged Windows", num_flagged)
                    
                    with col2:
                      
                        fig = create_timeline_plot(data, det_name)
                        if fig:
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.info("No flagged windows to display")

        except Exception as e:
            st.error(f"❌ Error: {e}")
            import traceback
            st.code(traceback.format_exc())
