"""
app.py - Streamlit Frontend and AI Q&A Dashboard for PCAP/PCAPNG HTTP Analysis.
Strictly abides by system constraints: Raw packet bytes are parsed locally via Scapy;
only structured JSON/Markdown context is passed to the Gemini LLM.
"""

import os
import tempfile
from dotenv import load_dotenv
import pandas as pd
import plotly.express as px
import streamlit as st
from google import genai
from google.genai import types

from pcap_parser import parse_pcap, serialize_transactions_for_rag

# Load environment variables from .env if present (force reload to pick up changes)
load_dotenv(override=True)

# ---------------------------------------------------------
# Streamlit Page Setup
# ---------------------------------------------------------
st.set_page_config(
    page_title="PCAP/PCAPNG HTTP Analyzer & AI Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for modern look and clear error badges
st.markdown("""
<style>
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 12px;
        border: 1px solid #e9ecef;
    }
    .badge-error {
        color: #dc3545;
        font-weight: bold;
    }
    .badge-ok {
        color: #28a745;
        font-weight: bold;
    }
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------
if "pcap_data" not in st.session_state:
    st.session_state["pcap_data"] = None

if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = []

if "loaded_file_name" not in st.session_state:
    st.session_state["loaded_file_name"] = None


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
def process_pcap_file(file_bytes: bytes, filename: str):
    """Saves bytes to temporary file, parses with Scapy, and updates session state."""
    suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        with st.spinner(f"Analyzing {filename} with Scapy (Reassembling TCP & HTTP streams)..."):
            result = parse_pcap(tmp_path)
            st.session_state["pcap_data"] = result
            st.session_state["loaded_file_name"] = filename
            st.session_state["chat_messages"] = []  # Reset chat for new file
    except Exception as e:
        st.error(f"Error parsing capture file: {e}")
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def style_status_codes(row):
    """Highlight HTTP error status codes (4xx and 5xx) visually in the DataFrame."""
    code = row.get("Status Code")
    if pd.notna(code):
        try:
            val = int(code)
            if 400 <= val < 500:
                # 4xx Client Error - light soft red/orange
                return ["background-color: rgba(255, 107, 107, 0.22); color: #c92a2a; font-weight: 600;"] * len(row)
            elif val >= 500:
                # 5xx Server Error - stronger reddish tint
                return ["background-color: rgba(224, 49, 49, 0.30); color: #a61e4d; font-weight: 700;"] * len(row)
            elif 200 <= val < 300:
                # 2xx Success - subtle green
                return ["background-color: rgba(64, 192, 87, 0.12); color: #2b8a3e;"] * len(row)
            elif 300 <= val < 400:
                # 3xx Redirect - subtle yellow
                return ["background-color: rgba(250, 176, 5, 0.15); color: #d9480f;"] * len(row)
        except (ValueError, TypeError):
            pass
    return [""] * len(row)


# ---------------------------------------------------------
# Sidebar: File Upload, Demo, Settings & Filters
# ---------------------------------------------------------
with st.sidebar:
    st.title("⚙️ Control Panel")

    # 1. PCAP Upload & Demo
    st.subheader("📁 Packet Capture File")
    uploaded_file = st.file_uploader(
        "Upload a .pcap or .pcapng file",
        type=["pcap", "pcapng"],
        help="Upload network trace for local Scapy analysis."
    )

    if uploaded_file is not None:
        if st.session_state["loaded_file_name"] != uploaded_file.name:
            file_bytes = uploaded_file.read()
            process_pcap_file(file_bytes, uploaded_file.name)

    sample_pcap_path = os.path.join(os.path.dirname(__file__), "sample.pcap")
    if os.path.exists(sample_pcap_path):
        col_demo1, col_demo2 = st.columns(2)
        with col_demo1:
            if st.button("🚀 Load Sample PCAP", use_container_width=True):
                with open(sample_pcap_path, "rb") as f:
                    process_pcap_file(f.read(), "sample.pcap")
                st.rerun()
        with col_demo2:
            sample_pcapng_path = os.path.join(os.path.dirname(__file__), "sample.pcapng")
            if os.path.exists(sample_pcapng_path):
                if st.button("📄 Sample PCAPNG", use_container_width=True):
                    with open(sample_pcapng_path, "rb") as f:
                        process_pcap_file(f.read(), "sample.pcapng")
                    st.rerun()

    st.divider()

    # 2. Gemini API Configuration
    st.subheader("🤖 Gemini AI Configuration")
    load_dotenv(override=True)
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    
    api_key_input = st.text_input(
        "Gemini API Key",
        value=env_key,
        type="password",
        help="Enter your Google Gemini API Key. Loaded automatically from .env if present."
    )
    model_choice = st.selectbox(
        "Model",
        ["gemini-3-flash-preview", "gemini-3.1-flash-lite-preview", "gemini-3.8-flash", "gemini-3.1-pro-preview"],
        index=0
    )

    effective_key = api_key_input.strip() if api_key_input.strip() else env_key
    if effective_key:
        st.success("API Key active", icon="🔑")
    else:
        st.warning("Enter Gemini API key to enable AI Q&A", icon="⚠️")

    st.divider()

    # 3. Interactive Filters (Requirements 4)
    st.subheader("🔍 Filter HTTP Transactions")
    data = st.session_state["pcap_data"]

    filter_status_codes = []
    filter_methods = []
    filter_host = ""
    filter_uri = ""
    errors_only = False

    if data and data["transactions"]:
        all_statuses = sorted(list({t["status_code"] for t in data["transactions"] if t["status_code"] is not None}))
        all_methods = sorted(list({t["method"] for t in data["transactions"] if t["method"]}))
        all_hosts = sorted(list({t["host"] for t in data["transactions"] if t["host"]}))

        errors_only = st.checkbox("🚨 HTTP Errors Only (4xx / 5xx)", value=False)
        filter_status_codes = st.multiselect("Status Code(s)", options=all_statuses, default=[])
        filter_methods = st.multiselect("HTTP Method(s)", options=all_methods, default=[])
        filter_hosts = st.multiselect("Filter by Host", options=all_hosts, default=[])
        filter_uri = st.text_input("Search URI / Path", placeholder="e.g. /api")
    else:
        filter_hosts = []
        st.info("Upload a file to enable filters.")


# ---------------------------------------------------------
# Main Application Content
# ---------------------------------------------------------
st.title("🌐 PCAP / PCAPNG HTTP Traffic Analyzer & AI Q&A")
st.caption(
    "🔒 **Architectural Guarantee:** Raw packet capture files are strictly decoded locally using Scapy. "
    "Only structured, sanitized HTTP transaction records are provided as context to Gemini AI."
)

data = st.session_state["pcap_data"]

if not data:
    st.info("👋 Welcome! Please upload a `.pcap` or `.pcapng` file from the sidebar, or click **'Load Sample PCAP'** to explore the dashboard.")
    st.stop()

summary = data["summary"]
transactions = data["transactions"]

# ---------------------------------------------------------
# Section 1: Capture Overview & Network Metrics
# ---------------------------------------------------------
st.header("📊 Capture Overview & General Metrics")

m1, m2, m3, m4, m5, m6 = st.columns(6)
with m1:
    st.metric("Total Packets", f"{summary['total_packets']:,}")
with m2:
    st.metric("Duration", f"{summary['duration_sec']} sec")
with m3:
    st.metric("Start Time", summary["start_time"].split()[-1] if summary["start_time"] != "N/A" else "N/A", help=summary["start_time"])
with m4:
    st.metric("End Time", summary["end_time"].split()[-1] if summary["end_time"] != "N/A" else "N/A", help=summary["end_time"])
with m5:
    st.metric("HTTP Transactions", summary["total_http_transactions"])
with m6:
    st.metric(
        "HTTP Errors (4xx/5xx)",
        summary["total_http_errors"],
        delta=f"{summary['total_http_errors']} errors" if summary["total_http_errors"] > 0 else "0",
        delta_color="inverse"
    )

# Visual Distribution Charts
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Protocol Distribution")
    proto_data = summary["protocol_counts"]
    if proto_data:
        proto_df = pd.DataFrame(list(proto_data.items()), columns=["Protocol", "Packets"])
        fig_proto = px.pie(
            proto_df,
            names="Protocol",
            values="Packets",
            hole=0.45,
            color_discrete_sequence=px.colors.qualitative.Safe,
            title="Protocols in Capture"
        )
        fig_proto.update_layout(margin=dict(t=30, b=10, l=10, r=10), height=300)
        st.plotly_chart(fig_proto, use_container_width=True)
    else:
        st.write("No protocol information available.")

with chart_col2:
    st.subheader("Top IP Endpoints (Top Talkers)")
    endpoints = summary["top_endpoints"]
    if endpoints:
        ep_df = pd.DataFrame(endpoints, columns=["IP Address", "Packet Count"]).sort_values("Packet Count", ascending=True)
        fig_ep = px.bar(
            ep_df,
            x="Packet Count",
            y="IP Address",
            orientation="h",
            color="Packet Count",
            color_continuous_scale="Blues",
            title="Most Active Endpoints"
        )
        fig_ep.update_layout(margin=dict(t=30, b=10, l=10, r=10), height=300)
        st.plotly_chart(fig_ep, use_container_width=True)
    else:
        st.write("No endpoints found.")

st.divider()

# ---------------------------------------------------------
# Section 2: Reassembled HTTP Transactions & Error Highlighting
# ---------------------------------------------------------
st.header("🔄 Reassembled HTTP Transactions")

# Apply Sidebar Filters
filtered_txs = transactions

if errors_only:
    filtered_txs = [t for t in filtered_txs if t["is_error"]]

if filter_status_codes:
    filtered_txs = [t for t in filtered_txs if t["status_code"] in filter_status_codes]

if filter_methods:
    filtered_txs = [t for t in filtered_txs if t["method"] in filter_methods]

if filter_hosts:
    filtered_txs = [t for t in filtered_txs if t["host"] in filter_hosts]

if filter_uri:
    filtered_txs = [t for t in filtered_txs if filter_uri.lower() in t["uri"].lower()]

col_tbl_info1, col_tbl_info2 = st.columns([3, 1])
with col_tbl_info1:
    st.markdown(f"Displaying **{len(filtered_txs)}** of **{len(transactions)}** transactions.")
with col_tbl_info2:
    if filtered_txs:
        csv_df = pd.DataFrame(filtered_txs)
        st.download_button(
            "📥 Export to CSV",
            csv_df.to_csv(index=False),
            file_name="http_transactions.csv",
            mime="text/csv",
            use_container_width=True
        )

if filtered_txs:
    table_rows = []
    for t in filtered_txs:
        table_rows.append({
            "ID": t["transaction_id"],
            "Method": t["method"],
            "Status Code": t["status_code"],
            "Reason": t["reason_phrase"],
            "Response Time (ms)": t["response_time_ms"],
            "Host": t["host"],
            "URI": t["uri"],
            "Client": f"{t['src_ip']}:{t['src_port']}",
            "Server": f"{t['dst_ip']}:{t['dst_port']}",
            "Req Frame #": t["req_frame_num"],
            "Resp Frame #": t["resp_frame_num"],
        })
    df_display = pd.DataFrame(table_rows)

    # Apply error color highlighting
    styled_df = df_display.style.apply(style_status_codes, axis=1)

    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "ID": st.column_config.NumberColumn(width="small"),
            "Method": st.column_config.TextColumn(width="small"),
            "Status Code": st.column_config.NumberColumn(width="small"),
            "Response Time (ms)": st.column_config.NumberColumn(format="%.1f ms"),
            "Req Frame #": st.column_config.NumberColumn(width="small"),
            "Resp Frame #": st.column_config.NumberColumn(width="small"),
        }
    )
else:
    st.warning("No transactions match the selected filters.")

st.divider()

# ---------------------------------------------------------
# Section 3: Deep Transaction Inspector
# ---------------------------------------------------------
st.header("🔎 Deep Transaction Inspector")

if transactions:
    tx_options = {
        f"Tx #{t['transaction_id']} | {t['method']} {t['uri']} -> {t['status_code']} ({t['response_time_ms']} ms)": t
        for t in transactions
    }
    selected_key = st.selectbox("Select a Transaction to Inspect Full Headers & Body:", list(tx_options.keys()))
    sel_tx = tx_options[selected_key]

    tab_overview, tab_req, tab_resp, tab_tcp = st.tabs([
        "📋 Overview", "📤 HTTP Request (Client)", "📥 HTTP Response (Server)", "🌐 TCP Stream & Timing"
    ])

    with tab_overview:
        c1, c2, c3, c4 = st.columns(4)
        c1.write(f"**Transaction ID:** #{sel_tx['transaction_id']}")
        c1.write(f"**Method:** `{sel_tx['method']}`")
        c2.write(f"**Status Code:** `{sel_tx['status_code']} {sel_tx['reason_phrase']}`")
        c2.write(f"**Host:** `{sel_tx['host']}`")
        c3.write(f"**Response Time:** `{sel_tx['response_time_ms']} ms` ({sel_tx['response_time_sec']}s)")
        c3.write(f"**Error Flag:** `{'🚨 Yes (4xx/5xx)' if sel_tx['is_error'] else '✅ No'}`")
        c4.write(f"**Request Frame:** `#{sel_tx['req_frame_num']}`")
        c4.write(f"**Response Frame:** `#{sel_tx['resp_frame_num']}`")
        st.write(f"**Full URI:** `{sel_tx['uri']}`")

    with tab_req:
        st.markdown(f"**Request Timestamp:** `{sel_tx['req_timestamp']}` (Frame `#{sel_tx['req_frame_num']}`)")
        st.write("**Request Headers:**")
        if sel_tx["req_headers"]:
            st.json(sel_tx["req_headers"])
        else:
            st.caption("No custom request headers.")

        st.write("**Request Body:**")
        if sel_tx["req_body"]:
            st.code(sel_tx["req_body"], language="json" if sel_tx["req_body"].startswith("{") else "text")
        else:
            st.caption("Empty body.")

    with tab_resp:
        st.markdown(f"**Response Timestamp:** `{sel_tx['resp_timestamp']}` (Frame `#{sel_tx['resp_frame_num']}`)")
        st.write("**Response Headers:**")
        if sel_tx["resp_headers"]:
            st.json(sel_tx["resp_headers"])
        else:
            st.caption("No custom response headers.")

        st.write("**Response Body:**")
        if sel_tx["resp_body"]:
            st.code(sel_tx["resp_body"], language="json" if sel_tx["resp_body"].startswith("{") else "html" if "<html" in sel_tx["resp_body"] else "text")
        else:
            st.caption("Empty body.")

    with tab_tcp:
        st.write(f"**TCP Stream Identifier:** `{sel_tx['tcp_stream_id']}`")
        st.write(f"**Client Endpoint:** `{sel_tx['src_ip']}:{sel_tx['src_port']}`")
        st.write(f"**Server Endpoint:** `{sel_tx['dst_ip']}:{sel_tx['dst_port']}`")
        st.write(f"**Calculated Round-Trip Latency:** `{sel_tx['response_time_ms']} ms`")

st.divider()

# ---------------------------------------------------------
# Section 4: AI Q&A Engine (Gemini API with RAG)
# ---------------------------------------------------------
st.header("💬 AI Assistant for Packet Analysis (Gemini RAG)")
st.caption(
    "Ask any question about the network capture. The assistant answers based strictly on the extracted structured HTTP dataset, "
    "citing exact **Frame Numbers** and **Timestamps** as evidence."
)

# Suggested Query Chips for Easy Testing
st.markdown("**💡 Suggested Queries (Matching Required Test Cases):**")
c_chip1, c_chip2, c_chip3, c_chip4 = st.columns(4)

suggested_prompt = None
if c_chip1.button("⏱️ Slowest Request (Test 1)", use_container_width=True):
    suggested_prompt = "What was the slowest HTTP request in the capture? What was its response time, method, URI, and frame numbers?"
if c_chip2.button("🏷️ Filter by Host (Test 2)", use_container_width=True):
    suggested_prompt = "How many requests were sent to host example.com? List their URIs, status codes, and frame numbers."
if c_chip3.button("🔍 Find 404 Status (Test 3)", use_container_width=True):
    suggested_prompt = "Did any request return status code 404? Cite the request URI, Host, response time, and exact frame numbers."
if c_chip4.button("🚫 Hallucination Test (Test 5)", use_container_width=True):
    suggested_prompt = "Did any client upload a sensitive file called 'credit_cards.csv' or send an SSH packet?"

# Display Chat History
for msg in st.session_state["chat_messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

user_query = st.chat_input("Ask a question about the capture (e.g. 'Explain the error on stream payment.gateway.io')...")
if suggested_prompt:
    user_query = suggested_prompt

if user_query:
    # Append user question to history
    st.session_state["chat_messages"].append({"role": "user", "content": user_query})
    with st.chat_message("user"):
        st.markdown(user_query)

    # Check for API Key (from text box or from .env)
    effective_key = api_key_input.strip() if api_key_input.strip() else os.environ.get("GEMINI_API_KEY", "").strip()
    if not effective_key:
        err_msg = "⚠️ **Gemini API Key Missing:** Please provide your API key in the sidebar to run AI queries."
        st.session_state["chat_messages"].append({"role": "assistant", "content": err_msg})
        with st.chat_message("assistant"):
            st.error(err_msg)
    else:
        with st.chat_message("assistant"):
            with st.spinner("Analyzing structured dataset with Gemini..."):
                try:
                    # 1. RAG Context Serialization (Core Requirement 3)
                    structured_rag_context = serialize_transactions_for_rag(transactions, summary)

                    # 2. Strict System Prompt (Core Requirement 3 & Hallucination Prevention)
                    system_prompt = (
                        "You are a specialized Network Protocol and Cyber Security Analysis assistant.\n"
                        "You are provided with a structured JSON dataset containing capture metrics and extracted HTTP transactions.\n\n"
                        "STRICT GROUNDING & EVIDENCE RULES:\n"
                        "1. All your statements MUST be based strictly and exclusively on the provided HTTP transactions and summary JSON block.\n"
                        "2. You MUST cite the specific 'req_frame' / 'resp_frame' (Frame Numbers) and/or exact timestamps as concrete evidence for every transaction you discuss.\n"
                        "3. NEVER fabricate or hallucinate transactions, files, hosts, IPs, or protocol events not present in the provided JSON data.\n"
                        "4. If the user asks about a file, protocol, or event that does NOT exist in the capture data (for example: SSH packets, files not requested, unknown users), you MUST explicitly state that it was not found in the capture data.\n"
                        "5. Provide crisp, technically accurate answers with markdown tables or bullet points where appropriate.\n"
                        "6. You may respond in the language used by the user (Hebrew or English)."
                    )

                    user_prompt_with_context = (
                        f"### STRUCTURED CAPTURE DATA (JSON):\n"
                        f"```json\n{structured_rag_context}\n```\n\n"
                        f"### USER QUESTION:\n{user_query}"
                    )

                    # 3. Call Modern Google GenAI SDK
                    client = genai.Client(api_key=effective_key)
                    response = client.models.generate_content(
                        model=model_choice,
                        contents=user_prompt_with_context,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            temperature=0.1,  # Low temperature for factual precision
                        )
                    )

                    ai_text = response.text
                    st.markdown(ai_text)
                    st.session_state["chat_messages"].append({"role": "assistant", "content": ai_text})

                except Exception as ex:
                    err_detail = f"❌ **Error generating response from Gemini API:** {ex}"
                    st.error(err_detail)
                    st.session_state["chat_messages"].append({"role": "assistant", "content": err_detail})
