"""
GRC Access Review Dashboard
Streamlit-based visualization layer for AWS Automated Access Review reports.

Pulls CSV report data from S3 and presents interactive security posture visualizations
for GRC stakeholders, auditors, and security engineers.

Author: Jacob Ferguson (JfergITLife)
"""

import streamlit as st
import pandas as pd
import boto3
import io
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="GRC Access Review Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# Custom Styling
# ──────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    /* Global */
    .stApp {
        font-family: 'IBM Plex Sans', sans-serif;
    }

    /* Header styling */
    .dashboard-header {
        background: linear-gradient(135deg, #0F2337 0%, #1a3a5c 50%, #0F2337 100%);
        padding: 2rem 2.5rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        border-left: 4px solid #C9A84C;
    }
    .dashboard-header h1 {
        color: #C9A84C;
        font-family: 'IBM Plex Sans', sans-serif;
        font-weight: 700;
        font-size: 2rem;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .dashboard-header p {
        color: #8fa8c8;
        font-size: 0.95rem;
        margin: 0.3rem 0 0 0;
        font-weight: 300;
    }

    /* Metric cards */
    .metric-card {
        background: #ffffff;
        border-radius: 10px;
        padding: 1.25rem 1.5rem;
        border: 1px solid #e8ecf1;
        border-top: 3px solid #0F2337;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .metric-card.critical { border-top-color: #dc3545; }
    .metric-card.high { border-top-color: #e8590c; }
    .metric-card.medium { border-top-color: #f59f00; }
    .metric-card.low { border-top-color: #2f9e44; }
    .metric-card.info { border-top-color: #1971c2; }

    .metric-value {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 2.25rem;
        font-weight: 500;
        line-height: 1;
        margin: 0.25rem 0;
    }
    .metric-label {
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #6c757d;
    }

    /* Section headers */
    .section-header {
        font-family: 'IBM Plex Sans', sans-serif;
        font-weight: 600;
        font-size: 1.1rem;
        color: #0F2337;
        border-bottom: 2px solid #C9A84C;
        padding-bottom: 0.5rem;
        margin: 1.5rem 0 1rem 0;
    }

    /* Findings table styling */
    .finding-row {
        background: #ffffff;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.5rem;
        border: 1px solid #e8ecf1;
        border-left: 4px solid #dee2e6;
    }
    .finding-row.severity-critical { border-left-color: #dc3545; }
    .finding-row.severity-high { border-left-color: #e8590c; }
    .finding-row.severity-medium { border-left-color: #f59f00; }
    .finding-row.severity-low { border-left-color: #2f9e44; }
    .finding-row.severity-informational { border-left-color: #1971c2; }

    /* Severity badges */
    .severity-badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'IBM Plex Mono', monospace;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-critical { background: #dc3545; color: white; }
    .badge-high { background: #e8590c; color: white; }
    .badge-medium { background: #f59f00; color: #1a1a1a; }
    .badge-low { background: #2f9e44; color: white; }
    .badge-informational { background: #1971c2; color: white; }

    /* Footer */
    .dashboard-footer {
        text-align: center;
        color: #6c757d;
        font-size: 0.8rem;
        padding: 2rem 0 1rem 0;
        border-top: 1px solid #e8ecf1;
        margin-top: 2rem;
    }

    /* Hide default streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none;}
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Color Maps
# ──────────────────────────────────────────────
SEVERITY_COLORS = {
    "Critical": "#dc3545",
    "High": "#e8590c",
    "Medium": "#f59f00",
    "Low": "#2f9e44",
    "Informational": "#1971c2",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


# ──────────────────────────────────────────────
# Data Loading
# ──────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_reports_from_s3(bucket_name, profile_name=None):
    """Load the most recent CSV report from S3."""
    try:
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
            s3 = session.client("s3")
        else:
            s3 = boto3.client("s3")

        # List all report files
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix="reports/")

        if "Contents" not in response:
            return None, None

        # Sort by last modified to get most recent
        reports = sorted(response["Contents"], key=lambda x: x["LastModified"], reverse=True)

        if not reports:
            return None, None

        # Get the most recent report
        latest_key = reports[0]["Key"]
        latest_modified = reports[0]["LastModified"]

        # Download and parse CSV
        obj = s3.get_object(Bucket=bucket_name, Key=latest_key)
        df = pd.read_csv(io.BytesIO(obj["Body"].read()))

        return df, latest_modified

    except Exception as e:
        st.error(f"Error loading from S3: {str(e)}")
        return None, None


def get_all_reports_from_s3(bucket_name, profile_name=None):
    """Get list of all available reports from S3."""
    try:
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
            s3 = session.client("s3")
        else:
            s3 = boto3.client("s3")

        response = s3.list_objects_v2(Bucket=bucket_name, Prefix="reports/")

        if "Contents" not in response:
            return []

        reports = sorted(response["Contents"], key=lambda x: x["LastModified"], reverse=True)
        return reports

    except Exception as e:
        st.error(f"Error listing reports: {str(e)}")
        return []


def load_specific_report(bucket_name, key, profile_name=None):
    """Load a specific report by S3 key."""
    try:
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
            s3 = session.client("s3")
        else:
            s3 = boto3.client("s3")

        obj = s3.get_object(Bucket=bucket_name, Key=key)
        df = pd.read_csv(io.BytesIO(obj["Body"].read()))
        return df

    except Exception as e:
        st.error(f"Error loading report: {str(e)}")
        return None


# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Configuration")

    bucket_name = st.text_input(
        "S3 Bucket Name",
        value="aws-access-review-reportbucket-fjmz5dmn8dgi",
        help="The S3 bucket where access review reports are stored",
    )

    aws_profile = st.text_input(
        "AWS Profile (optional)",
        value="",
        help="Leave blank to use default credentials",
    )
    profile = aws_profile if aws_profile else None

    st.markdown("---")

    # Report selector
    st.markdown("### 📋 Reports")
    reports = get_all_reports_from_s3(bucket_name, profile)

    if reports:
        report_options = {
            f"{r['Key'].split('/')[-1]} ({r['LastModified'].strftime('%Y-%m-%d %H:%M')})" : r['Key']
            for r in reports
        }
        selected_report = st.selectbox(
            "Select Report",
            options=list(report_options.keys()),
        )
        selected_key = report_options[selected_report]
    else:
        selected_key = None
        st.warning("No reports found in bucket.")

    st.markdown("---")
    st.markdown("### 🔍 Filters")

    severity_filter = st.multiselect(
        "Severity",
        options=SEVERITY_ORDER,
        default=SEVERITY_ORDER,
    )

    st.markdown("---")
    st.markdown(
        '<div style="text-align:center; color:#6c757d; font-size:0.75rem;">'
        "GRC Engineering Lab<br>JfergITLife"
        "</div>",
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────
st.markdown(
    '<div class="dashboard-header">'
    '<h1>🔒 GRC Access Review Dashboard</h1>'
    '<p>Automated AWS IAM Security Assessment &amp; Compliance Visualization</p>'
    "</div>",
    unsafe_allow_html=True,
)


# ──────────────────────────────────────────────
# Load Data
# ──────────────────────────────────────────────
if selected_key:
    df = load_specific_report(bucket_name, selected_key, profile)
else:
    df = None

if df is None or df.empty:
    st.warning("No report data available. Run an access review first, then refresh.")
    st.stop()

# Apply severity filter
df_filtered = df[df["severity"].isin(severity_filter)]

# ──────────────────────────────────────────────
# Severity Metrics Row
# ──────────────────────────────────────────────
severity_counts = df["severity"].value_counts()

col1, col2, col3, col4, col5 = st.columns(5)

for col, sev, css_class in zip(
    [col1, col2, col3, col4, col5],
    SEVERITY_ORDER,
    ["critical", "high", "medium", "low", "info"],
):
    count = severity_counts.get(sev, 0)
    color = SEVERITY_COLORS.get(sev, "#6c757d")
    with col:
        st.markdown(
            f'<div class="metric-card {css_class}">'
            f'<div class="metric-label">{sev}</div>'
            f'<div class="metric-value" style="color:{color}">{count}</div>'
            f"</div>",
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Charts Row
# ──────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown('<div class="section-header">Findings by Severity</div>', unsafe_allow_html=True)

    # Severity distribution donut chart
    sev_data = df_filtered["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0)
    fig_severity = go.Figure(
        data=[
            go.Pie(
                labels=sev_data.index,
                values=sev_data.values,
                hole=0.55,
                marker=dict(
                    colors=[SEVERITY_COLORS.get(s, "#6c757d") for s in sev_data.index]
                ),
                textinfo="label+value",
                textfont=dict(family="IBM Plex Sans", size=13),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
            )
        ]
    )
    fig_severity.update_layout(
        showlegend=False,
        margin=dict(t=20, b=20, l=20, r=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        annotations=[
            dict(
                text=f"<b>{len(df_filtered)}</b><br>Total",
                x=0.5, y=0.5,
                font=dict(size=20, family="IBM Plex Mono", color="#0F2337"),
                showarrow=False,
            )
        ],
    )
    st.plotly_chart(fig_severity, use_container_width=True)


with chart_col2:
    st.markdown('<div class="section-header">Findings by Category</div>', unsafe_allow_html=True)

    # Category bar chart
    cat_data = df_filtered["category"].value_counts()
    fig_category = go.Figure(
        data=[
            go.Bar(
                x=cat_data.values,
                y=cat_data.index,
                orientation="h",
                marker=dict(
                    color="#0F2337",
                    line=dict(color="#C9A84C", width=1),
                ),
                hovertemplate="<b>%{y}</b><br>Findings: %{x}<extra></extra>",
            )
        ]
    )
    fig_category.update_layout(
        margin=dict(t=20, b=20, l=20, r=20),
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            title="Count",
            gridcolor="#e8ecf1",
            title_font=dict(family="IBM Plex Sans", size=12, color="#6c757d"),
        ),
        yaxis=dict(
            title="",
            tickfont=dict(family="IBM Plex Sans", size=12),
        ),
    )
    st.plotly_chart(fig_category, use_container_width=True)


# ──────────────────────────────────────────────
# Compliance Coverage
# ──────────────────────────────────────────────
st.markdown('<div class="section-header">Compliance Framework Coverage</div>', unsafe_allow_html=True)

# Parse compliance data
compliance_counts = {}
for _, row in df_filtered.iterrows():
    comp = str(row.get("compliance", ""))
    if comp and comp != "nan" and comp != "N/A":
        for framework in comp.split(","):
            framework = framework.strip()
            if framework:
                compliance_counts[framework] = compliance_counts.get(framework, 0) + 1

if compliance_counts:
    comp_df = pd.DataFrame(
        list(compliance_counts.items()), columns=["Framework", "Findings"]
    ).sort_values("Findings", ascending=True)

    fig_comp = go.Figure(
        data=[
            go.Bar(
                x=comp_df["Findings"],
                y=comp_df["Framework"],
                orientation="h",
                marker=dict(color="#C9A84C", line=dict(color="#0F2337", width=1)),
                hovertemplate="<b>%{y}</b><br>Related Findings: %{x}<extra></extra>",
            )
        ]
    )
    fig_comp.update_layout(
        margin=dict(t=10, b=20, l=20, r=20),
        height=max(200, len(compliance_counts) * 40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            title="Related Findings",
            gridcolor="#e8ecf1",
            title_font=dict(family="IBM Plex Sans", size=12, color="#6c757d"),
        ),
        yaxis=dict(
            title="",
            tickfont=dict(family="IBM Plex Sans", size=11),
        ),
    )
    st.plotly_chart(fig_comp, use_container_width=True)
else:
    st.info("No compliance framework data available in this report.")


# ──────────────────────────────────────────────
# Findings Detail Table
# ──────────────────────────────────────────────
st.markdown('<div class="section-header">Detailed Findings</div>', unsafe_allow_html=True)

for _, row in df_filtered.iterrows():
    sev = row.get("severity", "Low")
    sev_lower = sev.lower()
    badge_class = f"badge-{sev_lower}"

    description = row.get("description", "No description")
    resource = f"{row.get('resource_type', 'N/A')}: {row.get('resource_id', 'N/A')}"
    recommendation = row.get("recommendation", "No recommendation provided")
    compliance = row.get("compliance", "N/A")
    category = row.get("category", "N/A")

    st.markdown(
        f'<div class="finding-row severity-{sev_lower}">'
        f'<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">'
        f'<span class="severity-badge {badge_class}">{sev}</span>'
        f'<span style="font-family:IBM Plex Mono; font-size:0.8rem; color:#6c757d;">{category}</span>'
        f"</div>"
        f'<div style="font-weight:500; color:#1a1a1a; margin-bottom:0.4rem;">{description}</div>'
        f'<div style="font-size:0.85rem; color:#495057; margin-bottom:0.3rem;">'
        f"<strong>Resource:</strong> {resource}</div>"
        f'<div style="font-size:0.85rem; color:#495057; margin-bottom:0.3rem;">'
        f"<strong>Recommendation:</strong> {recommendation}</div>"
        f'<div style="font-size:0.8rem; color:#6c757d;">'
        f"<strong>Compliance:</strong> {compliance}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────
# Raw Data Expander
# ──────────────────────────────────────────────
with st.expander("📊 View Raw Report Data"):
    st.dataframe(
        df_filtered,
        use_container_width=True,
        hide_index=True,
    )

    # Download button
    csv_buffer = io.StringIO()
    df_filtered.to_csv(csv_buffer, index=False)
    st.download_button(
        label="Download Filtered CSV",
        data=csv_buffer.getvalue(),
        file_name=f"access-review-filtered-{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv",
    )


# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────
st.markdown(
    '<div class="dashboard-footer">'
    "GRC Access Review Dashboard | Built by JfergITLife | "
    "Powered by AWS Security Hub, IAM Access Analyzer, CloudTrail &amp; Amazon Bedrock"
    "</div>",
    unsafe_allow_html=True,
)
