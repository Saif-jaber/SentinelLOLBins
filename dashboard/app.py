"""SentinelLOLBins analyst dashboard.

A prototype triage console for the alert records produced by ``score_event``.
It reads the committed demo and VM records together with the experiment outputs.
It does not retrain or reimplement scoring; manual and bulk events both go
through ``src.alert_scoring.score_event``.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import inspect
import json
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import altair as alt
import pandas as pd
import streamlit as st

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

RESULTS = BASE / "results"
RULES_DIR = BASE / "rules"
DATA = BASE / "data" / "processed"
DOCS = BASE / "docs"

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:
    pass

from rules.rule_engine import get_rules  # noqa: E402
from src.alert_scoring import ALERT_FIELDS, DISCLAIMER, AlertScorer, score_event  # noqa: E402
from src.vm_schema_adapter import (  # noqa: E402
    MANUAL_FEATURE_DEFAULTS,
    MODEL_INPUT_COLUMNS,
    compute_row_features,
)

RED = "#e5484d"
ORANGE = "#e8893a"
GREEN = "#30a46c"
BLUE = "#5a8dee"
GREY = "#8d8d9b"
RISK_COLOURS = {"low": GREEN, "medium": ORANGE, "high": RED}
DECISION_COLOURS = {"benign": GREEN, "malicious": RED}
RISK_ORDER = ["low", "medium", "high"]
# Bump when scoring code changes. Manual results from an older build are dropped
# so a stale alert cannot show an out-of-date risk band.
APP_STATE_VERSION = "2026-11-10.manual-triage.3"

DEMO_ALERTS = RESULTS / "sample_alerts.json"
DEMO_META = RESULTS / "sample_alerts_meta.csv"
VM_ALERTS = RESULTS / "vm_alerts.json"
VM_SUMMARY = RESULTS / "vm_summary.json"
VM_SCENARIOS = RESULTS / "vm_scenario_summary.csv"
MASTER_RESULTS = RESULTS / "master_results.csv"
TEST_OUTCOMES = RESULTS / "test_event_outcomes.csv"
THRESHOLD_PATH = RESULTS / "chosen_threshold.json"
FUSION_PATH = RESULTS / "fusion_config.json"
PR_FIGURE = RESULTS / "figures" / "pr_curve_test.png"
VM_MISSING_FIELDS = DOCS / "vm_missing_fields.txt"

SOURCE_OPTIONS = [
    "Demo alerts (synthetic)",
    "VM alerts (external check)",
    "Manual / uploaded",
    "All combined",
]

SCREENS = [
    "A. Triage overview",
    "B. Alert queue",
    "C. Alert detail",
    "D. Rules and ATT&CK",
    "E. Model and experiments",
    "F. VM external validation",
    "G. Manual event scorer",
    "H. Method and limitations",
]

DISPLAY_COLUMNS = [
    "risk",
    "decision",
    "review_required",
    "scored_at",
    "process_name",
    "parent_process",
    "user",
    "command_line",
    "rule_ids",
    "attack_techniques",
    "model_proba",
    "risk_score",
]


st.set_page_config(page_title="SentinelLOLBins", page_icon="S", layout="wide")


def inject_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --ink: #050608;
            --panel: #0c0d11;
            --panel-2: #12141a;
            --line: #22252d;
            --line-soft: #1b1e25;
            --text: #e7e9ee;
            --muted: #8b93a3;
            --accent: #ff3b3b;
            --accent-2: #ff7a45;
        }

        html, body, [class*="css"] {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                "Helvetica Neue", Arial, sans-serif;
        }

        .stApp {
            background-color: var(--ink);
            background-image:
                radial-gradient(1100px 560px at 12% -12%, rgba(255, 59, 59, .09), transparent 62%),
                radial-gradient(900px 520px at 100% -6%, rgba(64, 120, 255, .07), transparent 58%),
                radial-gradient(800px 700px at 60% 120%, rgba(255, 122, 69, .04), transparent 60%);
            background-attachment: fixed;
        }
        .stApp::before {
            content: "";
            position: fixed; top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent), var(--accent-2), transparent);
            z-index: 1000000;
        }

        [data-testid="stHeader"] { background: transparent; }
        #MainMenu { visibility: hidden; }
        footer { visibility: hidden; }

        .block-container {
            padding-top: 2.4rem;
            padding-bottom: 3rem;
            max-width: 1500px;
        }

        h1, h2, h3, h4 {
            color: var(--text);
            letter-spacing: -0.02em;
            font-weight: 700;
        }
        h1 {
            font-weight: 800;
            padding-bottom: .35rem;
            border-bottom: 1px solid var(--line-soft);
        }
        p, label, .stMarkdown { color: var(--text); }
        a { color: #ff6b6b; }

        /* Sidebar. */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #101116 0%, #0a0b0e 100%);
            border-right: 1px solid #1d2026;
            box-shadow: 8px 0 24px rgba(0, 0, 0, .45);
        }
        [data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
        [data-testid="stSidebar"] hr { border-color: #1d2026; }
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] .stMarkdown { color: #c3c9d4; }
        [data-testid="stSidebar"] [role="radiogroup"] label {
            padding: 8px 10px;
            border-radius: 9px;
            margin-bottom: 2px;
            border: 1px solid transparent;
            transition: background .13s ease, border-color .13s ease;
        }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            background: #16181e;
            border-color: #24272f;
        }

        .brand {
            display: flex; align-items: center; gap: 12px;
            padding: 12px 12px 14px 12px;
            margin-bottom: 14px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: linear-gradient(160deg, #15171d, #0b0c0f);
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, .03);
        }
        .brand-mark {
            width: 40px; height: 40px; flex: 0 0 40px;
            display: flex; align-items: center; justify-content: center;
            border-radius: 11px;
            font-weight: 800; font-size: .95rem; letter-spacing: .04em;
            color: #fff;
            background: linear-gradient(145deg, #ff4d4d, #b31717);
            box-shadow: 0 6px 16px rgba(200, 30, 30, .45),
                        inset 0 1px 0 rgba(255, 255, 255, .25);
        }
        .brand-name {
            font-weight: 800; font-size: 1.02rem; color: #fff;
            letter-spacing: -0.01em; line-height: 1.2;
        }
        .brand-sub {
            font-size: .74rem; color: var(--muted);
            text-transform: uppercase; letter-spacing: .12em;
        }

        /* Metric cards. */
        [data-testid="stMetric"] {
            background: linear-gradient(160deg, #12141a, #0a0b0e);
            border: 1px solid var(--line);
            border-radius: 14px;
            padding: 14px 16px 12px 16px;
            box-shadow: 0 10px 26px rgba(0, 0, 0, .38),
                        inset 0 1px 0 rgba(255, 255, 255, .025);
            transition: border-color .15s ease, transform .15s ease;
        }
        [data-testid="stMetric"]:hover {
            border-color: #333845;
            transform: translateY(-1px);
        }
        [data-testid="stMetricLabel"] {
            color: var(--muted) !important;
            text-transform: uppercase;
            letter-spacing: .09em;
            font-size: .7rem !important;
            font-weight: 600;
        }
        [data-testid="stMetricValue"] {
            color: #f4f6fa !important;
            font-weight: 700;
        }

        /* Bordered containers. */
        [data-testid="stVerticalBlockBorderWrapper"] {
            background: var(--panel);
            border: 1px solid var(--line) !important;
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, .32);
        }
        [data-testid="stVerticalBlockBorderWrapper"] > div {
            border-radius: 16px;
        }

        /* Buttons. */
        .stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
            background: linear-gradient(180deg, #1a1d24, #111318);
            color: var(--text);
            border: 1px solid #2b2f38;
            border-radius: 10px;
            font-weight: 600;
            letter-spacing: .01em;
            transition: all .15s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover,
        .stFormSubmitButton > button:hover {
            border-color: var(--accent);
            color: #fff;
            box-shadow: 0 0 0 1px rgba(255, 59, 59, .28),
                        0 0 18px rgba(255, 59, 59, .16);
        }
        .stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"],
        .stFormSubmitButton > button[kind="primary"] {
            background: linear-gradient(180deg, #ff4747, #c21b1b);
            border-color: #ff5f5f;
            color: #fff;
            box-shadow: 0 8px 20px rgba(200, 30, 30, .35);
        }
        .stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover {
            background: linear-gradient(180deg, #ff5b5b, #d42323);
            box-shadow: 0 10px 26px rgba(220, 40, 40, .45);
        }

        /* Inputs. */
        div[data-baseweb="input"], div[data-baseweb="textarea"],
        div[data-baseweb="select"] > div {
            background: #0f1116 !important;
            border-color: #2a2e37 !important;
            border-radius: 10px !important;
        }
        .stTextInput input, .stTextArea textarea, .stNumberInput input {
            background: transparent !important;
            color: var(--text) !important;
        }
        .stTextInput input:focus, .stTextArea textarea:focus {
            box-shadow: 0 0 0 1px rgba(255, 59, 59, .4) !important;
        }
        div[data-baseweb="input"]:focus-within,
        div[data-baseweb="textarea"]:focus-within,
        div[data-baseweb="select"] > div:focus-within {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 1px rgba(255, 59, 59, .28) !important;
        }
        div[data-baseweb="popover"] [role="listbox"] {
            background: #12141a;
            border: 1px solid var(--line);
        }
        div[data-baseweb="popover"] [role="option"]:hover {
            background: #1c1f27;
        }

        /* Uploader. */
        [data-testid="stFileUploaderDropzone"] {
            background: #0d0f14;
            border: 1px dashed #333845;
            border-radius: 12px;
        }
        [data-testid="stFileUploaderDropzone"]:hover { border-color: var(--accent); }

        /* Tabs. */
        .stTabs [data-baseweb="tab-list"] {
            gap: 6px;
            border-bottom: 1px solid var(--line);
        }
        .stTabs [data-baseweb="tab"] {
            background: transparent;
            color: var(--muted);
            border-radius: 9px 9px 0 0;
            padding: 8px 14px;
            font-weight: 600;
        }
        .stTabs [data-baseweb="tab"]:hover { color: var(--text); background: #14161c; }
        .stTabs [aria-selected="true"] {
            color: #fff !important;
            background: #16181e !important;
            border-bottom: 2px solid var(--accent);
        }

        /* Tables, code blocks, and expanders. */
        [data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 12px;
            overflow: hidden;
        }
        [data-testid="stExpander"] {
            background: var(--panel);
            border: 1px solid var(--line) !important;
            border-radius: 12px;
        }
        [data-testid="stExpander"] summary { font-weight: 600; }
        .stCode, pre, code {
            background: #0a0b0f !important;
            color: #cfd6e4 !important;
            border-radius: 8px;
        }
        hr { border-color: var(--line-soft); }

        /* Alerts. */
        [data-testid="stAlert"] {
            border-radius: 12px;
            border: 1px solid var(--line);
            background: #0d0f14;
        }

        /* Badges and banners. */
        .badge {
            display: inline-block; padding: 4px 14px; border-radius: 20px;
            font-weight: 700; color: #ffffff; letter-spacing: .02em;
            border: 1px solid rgba(255, 255, 255, .16);
            box-shadow: 0 4px 14px rgba(0, 0, 0, .35);
        }
        .proto-banner {
            border: 1px solid #4a3c22; background: linear-gradient(180deg, #241c10, #1a140b);
            color: #f0d9a8;
            border-radius: 12px; padding: 10px 16px; margin-bottom: 12px;
            font-size: .92rem;
        }
        .conflict {
            border: 1px solid #6a2c2c; background: linear-gradient(180deg, #261214, #1a0d0e);
            color: #ffb4b4;
            border-radius: 12px; padding: 10px 16px; margin: 8px 0;
        }
        .small-muted { color: var(--muted); font-size: .85rem; }

        /* Scrollbar. */
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: #08090c; }
        ::-webkit-scrollbar-thumb { background: #262a33; border-radius: 8px; }
        ::-webkit-scrollbar-thumb:hover { background: #3a3f4a; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def badge(text: str, colour: str) -> str:
    return f'<span class="badge" style="background:{colour}">{text}</span>'


def risk_badge(risk: Any) -> str:
    return badge(str(risk or "unknown").upper(), RISK_COLOURS.get(str(risk), GREY))


def decision_badge(decision: Any) -> str:
    return badge(
        str(decision or "unknown").upper(),
        DECISION_COLOURS.get(str(decision), GREY),
    )


def disclaimer_banner() -> None:
    st.markdown(f'<div class="proto-banner">{DISCLAIMER}</div>', unsafe_allow_html=True)


def chart_style(chart: alt.Chart, height: int = 280) -> alt.Chart:
    return (
        chart.properties(height=height, width="container")
        .configure(background="transparent")
        .configure_view(strokeWidth=0)
        .configure_axis(
            labelColor=GREY,
            titleColor=GREY,
            gridColor="#2a2a36",
            domainColor="#2a2a36",
        )
        .configure_legend(labelColor=GREY, titleColor=GREY)
    )


def to_native(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_native(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_native(v) for v in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return value
    if isinstance(value, float) and value != value:
        return None
    return value


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:
        return ""
    return str(value)


def join_list(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "; ".join(as_text(v) for v in value if as_text(v))
    return as_text(value)


def attack_url(technique: Any) -> str:
    text = as_text(technique).strip()
    if not text.upper().startswith("T"):
        return ""
    return "https://attack.mitre.org/techniques/" + "/".join(text.split(".")) + "/"


def attack_links(techniques: Iterable[Any]) -> str:
    links = []
    for technique in techniques or []:
        text = as_text(technique).strip()
        if not text:
            continue
        url = attack_url(text)
        links.append(f"[{text}]({url})" if url else text)
    return ", ".join(links)


@st.cache_data(show_spinner=False)
def load_json_records(path_str: str) -> List[Dict[str, Any]]:
    path = Path(path_str)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return [data]
    return list(data or [])


@st.cache_data(show_spinner=False)
def load_csv(path_str: str) -> pd.DataFrame:
    path = Path(path_str)
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


@st.cache_data(show_spinner=False)
def load_json_file(path_str: str) -> Dict[str, Any]:
    path = Path(path_str)
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


@st.cache_data(show_spinner=False)
def load_text(path_str: str) -> str:
    path = Path(path_str)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


@st.cache_data(show_spinner=False)
def load_rule_library() -> List[Dict[str, Any]]:
    try:
        return get_rules()
    except Exception:
        return []


@st.cache_resource(show_spinner=False)
def get_scorer() -> AlertScorer:
    return AlertScorer()


def _repair_risk(record: Dict[str, Any]) -> Dict[str, Any]:
    """Keep risk and decision consistent for stale/foreign stored alerts."""
    if (as_text(record.get("decision")).lower() == "malicious"
            and as_text(record.get("risk")).lower() == "low"):
        try:
            score = float(record.get("risk_score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        record = dict(record)
        record["risk"] = "high" if score >= 70 else "medium"
    return record


def alert_frame_from_records(records: List[Dict[str, Any]]) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=ALERT_FIELDS)
    frame = pd.DataFrame([_repair_risk(record) for record in records])
    for column in ALERT_FIELDS:
        if column not in frame.columns:
            frame[column] = None
    return frame


@st.cache_data(show_spinner=False)
def load_demo_alerts() -> pd.DataFrame:
    frame = alert_frame_from_records(load_json_records(str(DEMO_ALERTS)))
    if frame.empty:
        return frame
    meta = load_csv(str(DEMO_META))
    if not meta.empty and "event_id" in meta.columns:
        keep = [c for c in ["event_id", "expected_label", "outcome"] if c in meta.columns]
        frame = frame.merge(meta[keep], on="event_id", how="left")
    return frame


@st.cache_data(show_spinner=False)
def load_vm_alerts() -> pd.DataFrame:
    return alert_frame_from_records(load_json_records(str(VM_ALERTS)))


def manual_alerts_frame() -> pd.DataFrame:
    records = st.session_state.get("manual_alerts", [])
    frame = alert_frame_from_records(records)
    return frame


def get_alerts(source: str) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    if source in ("Demo alerts (synthetic)", "All combined"):
        demo = load_demo_alerts()
        if not demo.empty:
            demo = demo.copy()
            demo["_source"] = "demo (synthetic)"
            frames.append(demo)
    if source in ("VM alerts (external check)", "All combined"):
        vm = load_vm_alerts()
        if not vm.empty:
            vm = vm.copy()
            vm["_source"] = "vm (external check)"
            frames.append(vm)
    if source in ("Manual / uploaded", "All combined"):
        manual = manual_alerts_frame()
        if not manual.empty:
            manual = manual.copy()
            manual["_source"] = "manual / uploaded"
            frames.append(manual)
    if not frames:
        return pd.DataFrame(columns=list(ALERT_FIELDS) + ["_source"])
    frame = pd.concat(frames, ignore_index=True, sort=False)
    if "scored_at" in frame.columns:
        frame["_scored_dt"] = pd.to_datetime(frame["scored_at"], errors="coerce", utc=True)
    else:
        frame["_scored_dt"] = pd.NaT
    frame["_rule_ids_text"] = frame["rule_ids"].map(join_list)
    frame["_attack_text"] = frame["attack_techniques"].map(join_list)
    frame["_evidence_text"] = frame["evidence"].map(join_list)
    frame["_search_text"] = (
        frame[["command_line", "process_name", "parent_process", "_rule_ids_text",
               "_evidence_text", "_attack_text"]]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
        .str.lower()
    )
    return frame


def source_caption(source: str) -> None:
    notes = {
        "Demo alerts (synthetic)": "Synthetic WinLOLBIN-GT sample. Not real-world accuracy.",
        "VM alerts (external check)": "One isolated VM, limited scenarios. Not enterprise validation.",
        "Manual / uploaded": "Events scored live through score_event in this session.",
        "All combined": "Demo, VM and manual alerts combined. Sources stay labelled per row.",
    }
    st.caption(notes.get(source, ""))


def kpi_row(frame: pd.DataFrame) -> None:
    total = len(frame)
    high = int((frame["risk"] == "high").sum())
    medium = int((frame["risk"] == "medium").sum())
    low = int((frame["risk"] == "low").sum())
    malicious = int((frame["decision"] == "malicious").sum())
    benign = int((frame["decision"] == "benign").sum())
    review = int(frame["review_required"].fillna(False).astype(bool).sum())
    ruled = int(frame["rule_matched"].fillna(False).astype(bool).sum())
    mean_model = pd.to_numeric(frame["model_proba"], errors="coerce").mean()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", total)
    c2.metric("High / medium / low", f"{high} / {medium} / {low}")
    c3.metric("Predicted malicious / benign", f"{malicious} / {benign}")
    c4.metric("Review required", review)
    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Rule-matched alerts", ruled)
    c6.metric("Mean model probability", "-" if pd.isna(mean_model) else f"{mean_model:.3f}")
    if "expected_label" in frame.columns and frame["expected_label"].notna().any():
        expected = pd.to_numeric(frame["expected_label"], errors="coerce")
        c7.metric("Demo expected malicious", int((expected == 1).sum()))
        if "outcome" in frame.columns:
            counts = frame["outcome"].value_counts()
            c8.metric("Demo TP / FP / FN / TN",
                      f"{int(counts.get('TP', 0))} / {int(counts.get('FP', 0))} / "
                      f"{int(counts.get('FN', 0))} / {int(counts.get('TN', 0))}")
        else:
            c8.metric("Demo expected benign", int((expected == 0).sum()))
    else:
        c7.metric("Model threshold", f"{frame['model_threshold'].dropna().iloc[0]:.2f}"
                  if frame["model_threshold"].notna().any() else "-")
        c8.metric("Mean risk score", f"{pd.to_numeric(frame['risk_score'], errors='coerce').mean():.0f}")


def overview_charts(frame: pd.DataFrame) -> None:
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.subheader("Risk distribution")
            counts = (
                frame["risk"].fillna("unknown").value_counts().reindex(RISK_ORDER).fillna(0)
            )
            data = counts.rename_axis("risk").reset_index(name="count")
            chart = alt.Chart(data).mark_bar(cornerRadiusEnd=6).encode(
                x=alt.X("risk:N", sort=RISK_ORDER, title=None),
                y=alt.Y("count:Q", title="Alerts"),
                color=alt.Color("risk:N", scale=alt.Scale(
                    domain=list(RISK_COLOURS), range=list(RISK_COLOURS.values())), legend=None),
                tooltip=["risk", "count"],
            )
            st.altair_chart(chart_style(chart, 260))
    with right:
        with st.container(border=True):
            st.subheader("Decision by risk")
            working = frame.copy()
            working["risk"] = working["risk"].fillna("unknown")
            working["decision"] = working["decision"].fillna("unknown")
            pivot = (
                working.groupby(["risk", "decision"]).size().reset_index(name="count")
            )
            chart = alt.Chart(pivot).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X("risk:N", sort=RISK_ORDER, title=None),
                y=alt.Y("count:Q", title="Alerts"),
                color=alt.Color("decision:N", scale=alt.Scale(
                    domain=list(DECISION_COLOURS), range=list(DECISION_COLOURS.values()))),
                tooltip=["risk", "decision", "count"],
            )
            st.altair_chart(chart_style(chart, 260))

    left2, right2 = st.columns(2)
    with left2:
        with st.container(border=True):
            st.subheader("Top processes")
            top = frame["process_name"].fillna("unknown").value_counts().head(10)
            data = top.rename_axis("process").reset_index(name="count")
            chart = alt.Chart(data).mark_bar(color=ORANGE, cornerRadiusEnd=6).encode(
                x=alt.X("count:Q", title="Alerts"),
                y=alt.Y("process:N", sort="-x", title=None),
                tooltip=["process", "count"],
            )
            st.altair_chart(chart_style(chart, 300))
    with right2:
        with st.container(border=True):
            st.subheader("Top matched rules")
            exploded = frame[["rule_ids"]].explode("rule_ids")
            counts = exploded["rule_ids"].dropna().astype(str).value_counts().head(10)
            if counts.empty:
                st.info("No deterministic rule matched in this alert set.")
            else:
                data = counts.rename_axis("rule").reset_index(name="count")
                chart = alt.Chart(data).mark_bar(color=BLUE, cornerRadiusEnd=6).encode(
                    x=alt.X("count:Q", title="Alerts"),
                    y=alt.Y("rule:N", sort="-x", title=None),
                    tooltip=["rule", "count"],
                )
                st.altair_chart(chart_style(chart, 300))

    left3, right3 = st.columns(2)
    with left3:
        with st.container(border=True):
            st.subheader("ATT&CK technique suggestions")
            exploded = frame[["attack_techniques"]].explode("attack_techniques")
            counts = exploded["attack_techniques"].dropna().astype(str).value_counts().head(10)
            if counts.empty:
                st.info("No ATT&CK technique was suggested by the matched rules.")
            else:
                data = counts.rename_axis("technique").reset_index(name="count")
                chart = alt.Chart(data).mark_bar(color=ORANGE, cornerRadiusEnd=6).encode(
                    x=alt.X("count:Q", title="Alerts"),
                    y=alt.Y("technique:N", sort="-x", title=None),
                    tooltip=["technique", "count"],
                )
                st.altair_chart(chart_style(chart, 300))
    with right3:
        with st.container(border=True):
            st.subheader("Model / rule agreement")
            model = frame["model_pred"].fillna(0).astype(bool)
            rules = frame["rule_matched"].fillna(False).astype(bool)
            labels = pd.Series(
                ["both flag" if m and r else
                 "model only" if m and not r else
                 "rules only" if r and not m else "both clear"
                 for m, r in zip(model, rules)]
            )
            counts = labels.value_counts().rename_axis("agreement").reset_index(name="count")
            chart = alt.Chart(counts).mark_bar(color=GREEN, cornerRadiusEnd=6).encode(
                x=alt.X("count:Q", title="Alerts"),
                y=alt.Y("agreement:N", sort="-x", title=None),
                tooltip=["agreement", "count"],
            )
            st.altair_chart(chart_style(chart, 300))


def review_queue(frame: pd.DataFrame) -> None:
    queue = frame[frame["review_required"].fillna(False).astype(bool)]
    st.subheader("Review queue highlight")
    if queue.empty:
        st.success("No alert currently requires analyst review.")
        return
    st.warning(
        f"{len(queue)} alert(s) need review because the model and rule arms "
        "disagree or the parent-process context is unavailable."
    )
    columns = [c for c in ["risk", "decision", "process_name", "parent_process",
                           "command_line", "rule_ids", "model_proba"] if c in queue.columns]
    view = queue.sort_values("risk_score", ascending=False)[columns].copy()
    view["rule_ids"] = view["rule_ids"].map(join_list)
    st.dataframe(view.head(10), hide_index=True, width="stretch")


def screen_overview(frame: pd.DataFrame, source: str) -> None:
    st.title("Triage overview")
    disclaimer_banner()
    source_caption(source)
    if frame.empty:
        st.info("No alerts loaded for this source. Pick another source or score an event.")
        return
    kpi_row(frame)
    st.write("")
    overview_charts(frame)
    st.write("")
    review_queue(frame)


def filter_alerts(frame: pd.DataFrame) -> pd.DataFrame:
    filtered = frame.copy()
    with st.container(border=True):
        st.subheader("Filters")
        row1 = st.columns(4)
        risk_options = [r for r in RISK_ORDER if r in set(filtered["risk"].dropna())]
        risks = row1[0].multiselect("Risk", risk_options)
        decision_options = sorted(filtered["decision"].dropna().unique().tolist())
        decisions = row1[1].multiselect("Decision", decision_options)
        review_choice = row1[2].selectbox(
            "Review", ["all", "review required", "auto-cleared"])
        process_options = sorted(filtered["process_name"].dropna().astype(str).unique().tolist())
        processes = row1[3].multiselect("Process name", process_options)

        rule_values = (
            filtered["rule_ids"].explode().dropna().astype(str).unique().tolist()
        )
        attack_values = (
            filtered["attack_techniques"].explode().dropna().astype(str).unique().tolist()
        )
        row2 = st.columns(4)
        rule_ids = row2[0].multiselect("Rule ID", sorted(rule_values))
        attacks = row2[1].multiselect("ATT&CK technique", sorted(attack_values))
        scenarios = sorted(
            [s for s in filtered["scenario_id"].dropna().astype(str).unique().tolist() if s]
        )
        scenario_ids = row2[2].multiselect("Scenario", scenarios)
        search = row2[3].text_input("Free-text search (command, process, evidence)")

        row3 = st.columns(3)
        model_range = row3[0].slider("Model probability", 0.0, 1.0, (0.0, 1.0), 0.01)
        date_bounds = None
        if filtered["_scored_dt"].notna().any():
            minimum = filtered["_scored_dt"].min().date()
            maximum = filtered["_scored_dt"].max().date()
            date_bounds = row3[1].date_input(
                "Scored date range", value=(minimum, maximum),
                min_value=minimum, max_value=maximum,
            )
        sortable = ["risk_score", "model_proba", "scored_at", "process_name", "risk", "decision"]
        sort_by = row3[2].selectbox("Sort by", sortable, index=0)
        direction = st.radio("Sort direction", ["Descending", "Ascending"], horizontal=True)

    if risks:
        filtered = filtered[filtered["risk"].isin(risks)]
    if decisions:
        filtered = filtered[filtered["decision"].isin(decisions)]
    if review_choice == "review required":
        filtered = filtered[filtered["review_required"].fillna(False).astype(bool)]
    elif review_choice == "auto-cleared":
        filtered = filtered[~filtered["review_required"].fillna(False).astype(bool)]
    if processes:
        filtered = filtered[filtered["process_name"].astype(str).isin(processes)]
    if scenario_ids:
        filtered = filtered[filtered["scenario_id"].astype(str).isin(scenario_ids)]
    if rule_ids:
        filtered = filtered[
            filtered["rule_ids"].map(
                lambda values: bool(set(values or []) & set(rule_ids))
            )
        ]
    if attacks:
        filtered = filtered[
            filtered["attack_techniques"].map(
                lambda values: bool(set(values or []) & set(attacks))
            )
        ]
    model_values = pd.to_numeric(filtered["model_proba"], errors="coerce")
    filtered = filtered[model_values.between(model_range[0], model_range[1])]
    if search:
        filtered = filtered[filtered["_search_text"].str.contains(search.lower(), regex=False)]
    if date_bounds:
        if isinstance(date_bounds, (tuple, list)) and len(date_bounds) == 2:
            start, end = date_bounds
        else:
            start = end = date_bounds
        dates = filtered["_scored_dt"].dt.date
        filtered = filtered[(dates >= start) & (dates <= end)]

    ascending = direction == "Ascending"
    if sort_by in filtered.columns:
        filtered = filtered.sort_values(sort_by, ascending=ascending, na_position="last")
    return filtered.reset_index(drop=True)


def screen_queue(frame: pd.DataFrame, source: str) -> None:
    st.title("Alert queue")
    disclaimer_banner()
    source_caption(source)
    if frame.empty:
        st.info("No alerts available. Load a demo/VM source or score an event first.")
        return

    filtered = filter_alerts(frame)
    st.caption(f"{len(filtered)} of {len(frame)} alert(s) match the current filters.")

    if filtered.empty:
        st.info("No alerts match the current filters. Clear a filter to see alerts again.")
        return

    view = filtered[[c for c in DISPLAY_COLUMNS if c in filtered.columns]].copy()
    view["rule_ids"] = view["rule_ids"].map(join_list)
    view["attack_techniques"] = view["attack_techniques"].map(join_list)
    view["review_required"] = view["review_required"].map(
        lambda value: "yes" if bool(value) else "no"
    )
    if "_source" in filtered.columns:
        view.insert(0, "source", filtered["_source"].values)

    event = st.dataframe(
        view,
        hide_index=True,
        width="stretch",
        height=430,
        on_select="rerun",
        selection_mode="single-row",
        key="alert_queue_table",
    )

    export = filtered.drop(columns=[c for c in filtered.columns if c.startswith("_")], errors="ignore")
    st.download_button(
        "Export filtered alerts as CSV",
        data=export.to_csv(index=False),
        file_name="sentinel_queue.csv",
        mime="text/csv",
    )

    selected_rows = event.selection.rows if event and event.selection else []
    if selected_rows:
        row = filtered.iloc[selected_rows[0]]
        st.divider()
        st.subheader("Selected alert")
        render_alert_detail(row)


def review_reason(alert: Dict[str, Any]) -> str:
    reasons = []
    model_flag = bool(alert.get("model_pred"))
    rule_flag = bool(alert.get("rule_matched"))
    if model_flag != rule_flag:
        reasons.append("the model and rule arms disagree")
    if not as_text(alert.get("parent_process")):
        reasons.append("the parent process is unavailable")
    if not reasons:
        return "Not required: arms agree and parent context is present."
    return "Required because " + " and ".join(reasons) + "."


def render_alert_detail(alert: Any) -> None:
    if isinstance(alert, pd.Series):
        record = {k: to_native(v) for k, v in alert.to_dict().items() if k in ALERT_FIELDS}
    else:
        record = {k: to_native(alert.get(k)) for k in ALERT_FIELDS}
    record = _repair_risk(record)

    process = as_text(record.get("process_name")) or "unknown"
    parent = as_text(record.get("parent_process")) or "unknown"
    st.markdown(
        f"### {process} &nbsp;←&nbsp; {parent} &nbsp;&nbsp; "
        f"{risk_badge(record.get('risk'))} {decision_badge(record.get('decision'))}",
        unsafe_allow_html=True,
    )
    st.caption(
        f"event_id={as_text(record.get('event_id')) or '-'} | "
        f"record_id={as_text(record.get('record_id')) or '-'} | "
        f"scenario_id={as_text(record.get('scenario_id')) or '-'} | "
        f"scored_at={as_text(record.get('scored_at')) or '-'}"
    )

    meta1, meta2, meta3, meta4 = st.columns(4)
    meta1.metric("Risk", str(record.get("risk") or "-").upper())
    meta2.metric("Decision", str(record.get("decision") or "-").upper())
    meta3.metric("Risk score", record.get("risk_score", "-"))
    meta4.metric("Review required", "yes" if record.get("review_required") else "no")

    st.markdown("**Command line**")
    st.code(as_text(record.get("command_line")) or "(empty)", language="powershell")
    st.caption(
        f"User: {as_text(record.get('user')) or 'unknown'} | "
        f"process: {process} | parent: {parent}"
    )

    rule_col, model_col = st.columns(2)
    with rule_col:
        with st.container(border=True):
            st.subheader("Rule arm (evidence first)")
            rule_ids = record.get("rule_ids") or []
            st.metric("Rules matched", len(rule_ids))
            st.write(f"Severity max: **{record.get('rule_severity_max') or 'none'}**")
            if rule_ids:
                for rule_id, reason in zip(rule_ids, record.get("rule_reasons") or []):
                    st.markdown(f"- `{rule_id}` — {reason}")
            else:
                st.write("No deterministic rule matched.")
    with model_col:
        with st.container(border=True):
            st.subheader("Model arm")
            st.metric("Model probability", f"{float(record.get('model_proba') or 0):.4f}")
            st.write(
                f"XGBoost: **{float(record.get('xgb_proba') or 0):.4f}** "
                f"(pred {record.get('xgb_pred')})"
            )
            encoder = record.get("encoder_proba")
            st.write(f"SecureBERT: **{'-' if encoder is None else f'{float(encoder):.4f}'}**")
            st.write(
                f"Threshold: **{float(record.get('model_threshold') or 0):.2f}** | "
                f"prediction: **{record.get('model_pred')}**"
            )

    model_flag = bool(record.get("model_pred"))
    rule_flag = bool(record.get("rule_matched"))
    if model_flag != rule_flag:
        st.markdown(
            '<div class="conflict"><strong>Conflict retained.</strong> '
            "The model and the deterministic rules disagree. Both arms are shown; "
            "the alert stays in the review queue and no arm is deleted.</div>",
            unsafe_allow_html=True,
        )

    st.markdown("**ATT&CK suggestions**")
    techniques = record.get("attack_techniques") or record.get("rule_attack_ids") or []
    st.markdown(attack_links(techniques) or "None suggested by the matched rules.")
    rule_attack_ids = record.get("rule_attack_ids") or []
    if rule_attack_ids:
        st.caption("rule_attack_ids: " + ", ".join(as_text(t) for t in rule_attack_ids))
    st.caption("ATT&CK IDs are rule-derived suggestions, not ground truth.")

    st.markdown("**Hybrid decision**")
    hybrid1, hybrid2, hybrid3 = st.columns(3)
    hybrid1.metric("hybrid_score", record.get("hybrid_score"))
    hybrid2.metric("scoring_policy", as_text(record.get("scoring_policy")))
    hybrid3.metric("review_required", "yes" if record.get("review_required") else "no")
    st.write(review_reason(record))

    st.markdown("**Evidence**")
    evidence = record.get("evidence") or []
    if evidence:
        for line in evidence:
            st.markdown(f"- {line}")
    else:
        st.write("No evidence lines were produced.")

    st.markdown("**Model version**")
    st.json(record.get("model_version") or {})

    with st.expander("Raw alert JSON"):
        st.json(record)

    st.caption(as_text(record.get("disclaimer")) or DISCLAIMER)


def screen_detail(frame: pd.DataFrame, source: str) -> None:
    st.title("Alert detail")
    disclaimer_banner()
    source_caption(source)
    if frame.empty:
        st.info("No alerts available. Load a demo/VM source or score an event first.")
        return
    options = list(range(len(frame)))
    choice = st.selectbox(
        "Select an alert",
        options=options,
        format_func=lambda i: (
            f"{as_text(frame.iloc[i]['process_name']) or 'unknown'} | "
            f"{as_text(frame.iloc[i]['risk'])} | {as_text(frame.iloc[i]['event_id'])}"
        ),
    )
    render_alert_detail(frame.iloc[choice])


def describe_condition(node: Any) -> str:
    if isinstance(node, list):
        return " AND ".join(describe_condition(item) for item in node)
    if not isinstance(node, dict):
        return as_text(node)
    if "any" in node:
        return "(" + " OR ".join(describe_condition(n) for n in node.get("any") or []) + ")"
    if "all" in node:
        return "(" + " AND ".join(describe_condition(n) for n in node.get("all") or []) + ")"
    if "not" in node:
        return "NOT " + describe_condition((node.get("not") or [{}])[0])
    parts = []
    for key in ("process_is", "parent_is", "command_line_regex", "path_regex"):
        if key in node and node[key] is not None:
            value = node[key]
            if isinstance(value, list):
                value = " OR ".join(as_text(v) for v in value)
            parts.append(f"{key}={as_text(value)}")
    return " AND ".join(parts) if parts else "{condition}"


def rule_match_counts(frame: pd.DataFrame) -> Dict[str, int]:
    if frame.empty:
        return {}
    exploded = frame[["rule_ids"]].explode("rule_ids")
    counts = exploded["rule_ids"].dropna().astype(str).value_counts()
    return {str(k): int(v) for k, v in counts.items()}


def screen_rules(frame: pd.DataFrame, source: str) -> None:
    st.title("Rules and ATT&CK reference")
    disclaimer_banner()
    source_caption(source)
    rules = load_rule_library()
    if not rules:
        st.error("Could not load rules from rules/*.yml.")
        return
    counts = rule_match_counts(frame)
    rows = []
    for rule in rules:
        rows.append({
            "rule_id": as_text(rule.get("id")),
            "title": as_text(rule.get("title")),
            "severity": as_text(rule.get("severity")),
            "applies_to_process": ", ".join(
                as_text(v) for v in (
                    rule.get("applies_to_process")
                    if isinstance(rule.get("applies_to_process"), list)
                    else [rule.get("applies_to_process")]
                ) if as_text(v)
            ) or "any process",
            "attack": ", ".join(
                as_text(v) for v in (
                    rule.get("attack")
                    if isinstance(rule.get("attack"), list)
                    else [rule.get("attack")]
                ) if as_text(v)
            ),
            "condition": describe_condition(rule.get("conditions")),
            "reason": as_text(rule.get("reason")),
            "reference": ", ".join(
                as_text(v) for v in (
                    rule.get("references")
                    if isinstance(rule.get("references"), list)
                    else [rule.get("references")]
                ) if as_text(v)
            ),
            "matches_current_set": counts.get(as_text(rule.get("id")), 0),
        })
    library = pd.DataFrame(rows)
    st.caption(f"{len(library)} deterministic Sigma-style rules loaded from rules/*.yml.")
    st.dataframe(library, hide_index=True, width="stretch", height=560)

    st.subheader("ATT&CK technique coverage")
    techniques = []
    for rule in rules:
        attack = rule.get("attack")
        values = attack if isinstance(attack, list) else [attack]
        for value in values:
            if as_text(value):
                techniques.append({
                    "technique": as_text(value),
                    "rule_id": as_text(rule.get("id")),
                    "title": as_text(rule.get("title")),
                    "link": attack_url(value),
                })
    if techniques:
        st.dataframe(pd.DataFrame(techniques), hide_index=True, width="stretch")
    st.caption("ATT&CK mappings are curated rule metadata and remain suggestions.")


def confusion_and_metrics() -> Optional[Dict[str, Any]]:
    outcomes = load_csv(str(TEST_OUTCOMES))
    if outcomes.empty or "true" not in outcomes.columns or "proba" not in outcomes.columns:
        return None
    threshold = float(load_json_file(str(THRESHOLD_PATH)).get("threshold", 0.55))
    truth = pd.to_numeric(outcomes["true"], errors="coerce")
    proba = pd.to_numeric(outcomes["proba"], errors="coerce")
    valid = truth.notna() & proba.notna()
    truth = truth[valid].astype(int)
    pred = (proba[valid] >= threshold).astype(int)
    tp = int(((truth == 1) & (pred == 1)).sum())
    fp = int(((truth == 0) & (pred == 1)).sum())
    fn = int(((truth == 1) & (pred == 0)).sum())
    tn = int(((truth == 0) & (pred == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "n": int(len(truth)),
    }


def confusion_chart(metrics: Dict[str, Any]) -> alt.Chart:
    data = pd.DataFrame([
        {"actual": "malicious", "predicted": "malicious", "count": metrics["tp"]},
        {"actual": "malicious", "predicted": "benign", "count": metrics["fn"]},
        {"actual": "benign", "predicted": "malicious", "count": metrics["fp"]},
        {"actual": "benign", "predicted": "benign", "count": metrics["tn"]},
    ])
    return alt.Chart(data).mark_rect().encode(
        x=alt.X("predicted:N", title="Predicted", sort=["malicious", "benign"]),
        y=alt.Y("actual:N", title="Actual", sort=["malicious", "benign"]),
        color=alt.Color("count:Q", scale=alt.Scale(scheme="orangered")),
        tooltip=["actual", "predicted", "count"],
    ).properties(height=260, width=300)


def screen_performance(frame: pd.DataFrame, source: str) -> None:
    st.title("Model and experiment performance")
    st.info("Synthetic WinLOLBIN-GT results. These are not real-world accuracy claims.")
    source_caption(source)
    master = load_csv(str(MASTER_RESULTS))
    threshold_cfg = load_json_file(str(THRESHOLD_PATH))
    fusion_cfg = load_json_file(str(FUSION_PATH))

    if master.empty:
        st.error("results/master_results.csv is missing, so measured metrics cannot be shown.")
    else:
        experiments = sorted(master["experiment"].dropna().unique().tolist())
        chosen = st.multiselect("Experiments", experiments, default=experiments)
        shown = master[master["experiment"].isin(chosen)]
        columns = [c for c in ["experiment", "dataset", "model", "threshold", "precision",
                               "recall", "f1", "fpr", "holdout_recall", "notes"]
                   if c in shown.columns]
        st.dataframe(shown[columns], hide_index=True, width="stretch", height=360)
        st.caption("E1 rules-only · E2 XGBoost vs SecureBERT · E2 fusion · E3 ablation · "
                   "E4 holdout · E5 hybrid-with-rules.")

    benign = load_csv(str(RESULTS / "benign_heavy_results.csv"))
    if not benign.empty:
        st.subheader("Benign-heavy 1:100 false-alarm tradeoff")
        chart = alt.Chart(benign).mark_line(point=True, color=ORANGE).encode(
            x=alt.X("threshold:Q", title="Threshold"),
            y=alt.Y("fp_per_10k_benign:Q", title="False alarms per 10k benign"),
            tooltip=["threshold", "precision", "recall", "f1", "fp_per_10k_benign"],
        )
        st.altair_chart(chart_style(chart, 280))
        st.dataframe(benign, hide_index=True, width="stretch")

    metrics = confusion_and_metrics()
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.subheader("Confusion matrix, test split")
            if metrics:
                st.altair_chart(confusion_chart(metrics))
                st.caption(
                    f"Threshold {metrics['threshold']:.2f} · n={metrics['n']} · "
                    f"TP {metrics['tp']} / FP {metrics['fp']} / FN {metrics['fn']} / TN {metrics['tn']}"
                )
            else:
                st.info("test_event_outcomes.csv is missing true/proba columns.")
    with right:
        with st.container(border=True):
            st.subheader("Precision-recall curve")
            if PR_FIGURE.exists():
                st.image(str(PR_FIGURE), width="stretch")
            elif metrics:
                st.write(
                    f"Precision {metrics['precision']:.4f} · Recall {metrics['recall']:.4f} · "
                    f"F1 {metrics['f1']:.4f} · FPR {metrics['fpr']:.4f}"
                )
            else:
                st.info("PR curve figure is missing.")

    if metrics:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{metrics['precision']:.4f}")
        m2.metric("Recall", f"{metrics['recall']:.4f}")
        m3.metric("F1", f"{metrics['f1']:.4f}")
        m4.metric("False-positive rate", f"{metrics['fpr']:.4f}")

    latency = load_csv(str(RESULTS / "latency.csv"))
    st.subheader("Inference latency")
    if latency.empty:
        st.info("results/latency.csv is missing.")
    else:
        st.dataframe(latency, hide_index=True, width="stretch")

    st.subheader("Frozen configuration")
    config_left, config_right = st.columns(2)
    with config_left:
        st.markdown("**Threshold**")
        st.json(threshold_cfg or {"error": "chosen_threshold.json missing"})
    with config_right:
        st.markdown("**Fusion**")
        st.json(fusion_cfg or {"error": "fusion_config.json missing"})


def missing_field_rows() -> List[Dict[str, Any]]:
    text = load_text(str(VM_MISSING_FIELDS))
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if "/32 missing" in stripped:
            field, detail = stripped.split(":", 1)
            rows.append({"feature": field.strip(), "detail": detail.strip()})
    return rows


def screen_vm(frame: pd.DataFrame, source: str) -> None:
    st.title("VM external validation")
    st.error(
        "External check only, one VM, not enterprise validation. It is not a "
        "real-world performance estimate."
    )
    summary = load_json_file(str(VM_SUMMARY))
    scenarios = load_csv(str(VM_SCENARIOS))
    if not summary:
        st.info("results/vm_summary.json is missing, so the external check cannot be shown.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("VM events", summary.get("n_events", "-"))
    c2.metric("Scenarios", summary.get("n_scenarios", "-"))
    c3.metric("Attack scenarios", summary.get("n_attack_scenarios", "-"))
    c4.metric("Benign scenarios", summary.get("n_benign_scenarios", "-"))

    arm_rows = []
    for arm, label in [("xgb", "XGBoost"), ("rules", "Rules"), ("hybrid", "Hybrid")]:
        arm_rows.append({
            "arm": label,
            "attack_scenario_recall": summary.get(f"attack_scenario_recall_{arm}"),
            "benign_scenario_fp_rate": summary.get(f"benign_scenario_fp_rate_{arm}"),
            "event_tp": summary.get(f"event_tp_{arm}"),
            "event_fp": summary.get(f"event_fp_{arm}"),
            "event_fn": summary.get(f"event_fn_{arm}"),
        })
    st.subheader("Arm comparison")
    st.dataframe(pd.DataFrame(arm_rows), hide_index=True, width="stretch")
    st.warning(
        "Critical caveat: XGBoost flagged every VM event, so its attack-scenario recall "
        "and benign-scenario false-positive rate are both 1.0. This is a transfer and "
        "calibration mismatch, not good performance."
    )

    missing = missing_field_rows()
    st.subheader("Model-input limitations")
    st.write(f"{len(missing)} model-input features are missing for raw VM telemetry.")
    if missing:
        st.dataframe(pd.DataFrame(missing), hide_index=True, width="stretch")
    with st.expander("Full missing-fields report"):
        st.code(load_text(str(VM_MISSING_FIELDS)) or "docs/vm_missing_fields.txt missing")

    st.subheader("Scenario table")
    if scenarios.empty:
        st.info("results/vm_scenario_summary.csv is missing.")
    else:
        view = scenarios.copy()
        if "expected_label" in view.columns:
            view["expected"] = view["expected_label"].map(
                lambda value: "attack" if value == 1 else "benign")
        keep = [c for c in ["scenario_id", "expected", "technique_expected", "n_events",
                            "n_flagged_xgb", "n_flagged_rules", "n_flagged_hybrid"]
                if c in view.columns]
        st.dataframe(view[keep], hide_index=True, width="stretch")

    st.caption(str(summary.get("disclaimer", "")))


def _pick_column(frame: pd.DataFrame, names: Iterable[str]) -> Optional[str]:
    lookup = {str(col).strip().lower().replace(" ", "").replace("-", "_"): col
              for col in frame.columns}
    for name in names:
        key = name.lower().replace(" ", "").replace("-", "_")
        if key in lookup:
            return lookup[key]
    return None


def score_manual_event(command: str, process: str, parent: str, user: str,
                       scenario: str) -> Dict[str, Any]:
    command = as_text(command).strip()
    process = as_text(process).strip() or "unknown.exe"
    parent = as_text(parent).strip()
    raw = {
        "Image": process,
        "ParentImage": parent,
        "CommandLine": command,
        "User": user,
        "scenario_id": scenario,
    }
    features = compute_row_features(raw, None)
    for key, default in MANUAL_FEATURE_DEFAULTS.items():
        value = features.get(key)
        if value is None or (isinstance(value, float) and value != value):
            features[key] = default
    digest = hashlib.sha1(
        f"{command}|{process}|{parent}".encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    row = {
        **features,
        "CommandLine": command,
        "command_line": command,
        "User": as_text(user).strip() or None,
        "scenario_id": as_text(scenario).strip() or None,
        "record_id": f"manual_{digest}",
    }
    return score_event(row, manual=True)


def remember_alert(alert: Dict[str, Any]) -> None:
    log = st.session_state.setdefault("manual_alerts", [])
    log = [item for item in log if item.get("event_id") != alert.get("event_id")]
    log.insert(0, to_native(alert))
    st.session_state["manual_alerts"] = log


def screen_manual(frame: pd.DataFrame, source: str) -> None:
    st.title("Manual event scorer")
    disclaimer_banner()
    st.caption(
        "This screen calls score_event() directly; it does not re-implement scoring."
    )
    st.write(
        "Missing model inputs are computed from the raw event with the same adapter used "
        "for VM telemetry; 14 unrecoverable features stay at documented defaults. Because "
        "hand-typed events are out-of-distribution for the frozen model, the band uses a "
        "transparent rules+indicator triage: strong evidence (encoded/hidden/download "
        "flags, remote URL/UNC, proxy execution, high-risk process with a file path) or a "
        "high/critical rule -> HIGH; weak evidence -> MEDIUM; otherwise LOW. The "
        "executable named in the command line drives process-specific checks; the "
        "Process/Parent fields are context and cannot escalate a normal command on "
        "their own. The raw model probability is kept as evidence."
    )

    with st.form("manual_event_form"):
        command = st.text_area(
            "Command line", height=120,
            value="powershell.exe -nop -w hidden -enc SQBFAFgA",
        )
        row1 = st.columns(3)
        process = row1[0].text_input("Process name", value="powershell.exe")
        parent = row1[1].text_input("Parent process", value="explorer.exe")
        user = row1[2].text_input("User", value="analyst")
        scenario = st.text_input("Scenario ID (optional)", value="MANUAL-001")
        submitted = st.form_submit_button("Score event", type="primary")

    if submitted:
        if not command.strip():
            st.error("Enter a command line first.")
        else:
            try:
                alert = score_manual_event(
                    command.strip(), process.strip() or "unknown.exe",
                    parent.strip(), user.strip(), scenario.strip(),
                )
                remember_alert(alert)
                st.session_state["last_manual_alert"] = alert
                st.success("Event scored through score_event().")
            except Exception as exc:
                st.error(f"Scoring failed: {exc}")

    last = st.session_state.get("last_manual_alert")
    if last:
        st.divider()
        st.caption("Result for the last submitted event. Press Score event after changing the form.")
        render_alert_detail(last)

    st.divider()
    st.subheader("Batch CSV upload (optional)")
    st.caption(
        "Required columns: CommandLine (or Command/Command_Line/Cmd), "
        "Image (or Process/ProcessName/ImagePath). Optional: "
        "ParentImage (or Parent/ParentProcess), User, scenario_id. "
        "Header matching is case/space insensitive."
    )
    uploaded = st.file_uploader("Upload events CSV", type=["csv"], key="batch_upload")
    if uploaded is not None:
        try:
            batch = pd.read_csv(
                uploaded, dtype=str, keep_default_na=False, encoding="utf-8-sig"
            )
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")
            batch = pd.DataFrame()
        if not batch.empty:
            col_cmd = _pick_column(
                batch, ["CommandLine", "command_line", "Command", "Cmd"])
            col_img = _pick_column(
                batch, ["Image", "Process", "ProcessName", "ImagePath", "ProcessPath"])
            col_par = _pick_column(
                batch, ["ParentImage", "Parent", "ParentProcess", "ParentName"])
            col_user = _pick_column(batch, ["User", "UserName"])
            col_scen = _pick_column(batch, ["scenario_id", "ScenarioId", "Scenario"])
            missing = [label for label, col in
                       [("CommandLine", col_cmd), ("Image", col_img)] if col is None]
            if missing:
                st.error(f"CSV is missing required columns: {missing}")
            else:
                if st.button("Score uploaded CSV"):
                    alerts = []
                    errors = 0
                    with st.spinner("Scoring uploaded events..."):
                        for _, row in batch.iterrows():
                            try:
                                alerts.append(score_manual_event(
                                    as_text(row.get(col_cmd)),
                                    as_text(row.get(col_img)) or "unknown.exe",
                                    as_text(row.get(col_par)) if col_par else "",
                                    as_text(row.get(col_user)) if col_user else "",
                                    as_text(row.get(col_scen)) if col_scen else "",
                                ))
                            except Exception:
                                errors += 1
                    st.session_state["batch_result"] = alerts
                    if errors:
                        st.warning(f"{errors} row(s) could not be scored.")
                    if alerts:
                        st.success(f"Scored {len(alerts)} event(s).")

    batch_result = st.session_state.get("batch_result") or []
    if batch_result:
        batch_frame = pd.DataFrame(batch_result)
        st.markdown("**Batch risk distribution**")
        risk_counts = batch_frame["risk"].astype(str).str.lower().value_counts()
        counter_low, counter_medium, counter_high = st.columns(3)
        counter_low.metric("Low risk", int(risk_counts.get("low", 0)))
        counter_medium.metric("Medium risk", int(risk_counts.get("medium", 0)))
        counter_high.metric("High risk", int(risk_counts.get("high", 0)))
        st.caption(f"Counters cover {len(batch_frame)} scored event(s).")
        st.dataframe(
            batch_frame[[c for c in ["risk", "decision", "process_name", "parent_process",
                                     "command_line", "rule_ids", "model_proba"]
                        if c in batch_frame.columns]],
            hide_index=True, width="stretch",
        )
        st.download_button(
            "Download scored CSV",
            data=batch_frame.to_csv(index=False),
            file_name="scored_events.csv",
            mime="text/csv",
        )
        if st.button("Save batch to manual alert log"):
            for alert in batch_result:
                remember_alert(alert)
            st.success("Batch alerts saved to the manual log.")


def dependency_versions() -> pd.DataFrame:
    packages = ["pandas", "numpy", "scikit-learn", "xgboost", "streamlit",
                "altair", "matplotlib", "pyarrow", "PyYAML"]
    rows = []
    for package in packages:
        try:
            rows.append({"package": package, "version": md.version(package)})
        except md.PackageNotFoundError:
            rows.append({"package": package, "version": "not installed"})
    return pd.DataFrame(rows)


def screen_method(frame: pd.DataFrame, source: str) -> None:
    st.title("Method and limitations")
    st.markdown(
        """
        **Dataset.** WinLOLBIN-GT 1.0.1, used as a labelled Windows
        process-creation corpus. Analysis runs on a 100k sample with grouped
        train/validation/test/holdout splits so command templates do not cross
        splits.

        **Three detection arms.** Deterministic Sigma-style rules (E1), XGBoost
        with full process/command context, and a frozen SecureBERT command-text
        encoder (E2). The validation-selected fusion is a weighted average of
        calibrated probabilities.

        **Fusion policy.** `model_pred OR high/critical severity rule` for the
        conservative alert record. `review_required` keeps model/rule conflicts
        and missing parent context for analyst triage. Thresholds are frozen once
        on validation only.

        **Evaluation.** E1 rules-only, E2 model comparison and fusion, E3 feature
        ablation, E4 held-out techniques, E5 hybrid-with-rules, benign-heavy
        1:100 prevalence, grouped confidence intervals, and latency. Test and
        holdout are scored after configuration is frozen.
        """
    )
    st.subheader("Reproducibility commands")
    st.code(
        "python src/audit_dataset.py\n"
        "python src/preprocess.py\n"
        "python src/make_splits.py\n"
        "python src/train_xgb.py\n"
        "python src/train_encoder.py\n"
        "python src/threshold_and_uncertainty.py\n"
        "python src/hybrid_fusion.py\n"
        "python src/ablation_e3.py\n"
        "python src/eval_holdout.py\n"
        "python src/benign_heavy_test.py\n"
        "python src/hybrid_rules.py\n"
        "python src/alert_scoring.py --input results/test_event_outcomes.csv "
        "--proba-col proba --label-col true --per-outcome 8 --prefix sample_alerts\n"
        "python src/score_vm.py\n"
        "streamlit run dashboard/app.py",
        language="powershell",
    )
    st.subheader("Scope, ethics and limitations")
    st.markdown(
        """
        - Prototype only: not an EDR, not autonomous response, and not validated
          for enterprise deployment.
        - Risk is a triage priority; it is not a verdict that compromise occurred.
        - Rules are evidence, not ground truth. ATT&CK IDs are suggestions.
        - Demo alerts are synthetic and must be labelled as such.
        - The VM check covers one isolated VM and only the scenarios that ran
          there; 14 model inputs were unavailable and XGBoost over-flagged.
        - VM testing requires authorisation and must stay inside the isolated lab.
        - No real-world accuracy is claimed anywhere in this dashboard.
        """
    )
    st.subheader("Runtime dependencies")
    st.dataframe(dependency_versions(), hide_index=True, width="stretch")


def sidebar() -> tuple[str, str]:
    with st.sidebar:
        st.markdown(
            '<div class="brand">'
            '<div class="brand-mark">SL</div>'
            '<div><div class="brand-name">SentinelLOLBins</div>'
            '<div class="brand-sub">LOLBin alert triage</div></div>'
            "</div>",
            unsafe_allow_html=True,
        )
        source = st.radio("Alert source", SOURCE_OPTIONS, index=0)
        st.divider()
        screen = st.radio("Screen", SCREENS, index=0)
        st.divider()
        manual_count = len(st.session_state.get("manual_alerts", []))
        st.caption(f"Manual alerts in this session: {manual_count}")
        if st.button("Clear manual alert log"):
            st.session_state["manual_alerts"] = []
            st.session_state.pop("last_manual_alert", None)
            st.session_state.pop("batch_result", None)
            st.rerun()
        st.divider()
        st.caption("Prototype only. Not an EDR. Risk is triage priority.")
        st.caption("Rules are evidence, not ground truth.")
    return source, screen


def main() -> None:
    inject_css()
    if st.session_state.get("_app_state_version") != APP_STATE_VERSION:
        for key in ("last_manual_alert", "manual_alerts", "batch_result"):
            st.session_state.pop(key, None)
        st.session_state["_app_state_version"] = APP_STATE_VERSION
    if "manual" not in inspect.signature(score_event).parameters:
        st.sidebar.error(
            "The loaded scoring backend is stale (score_event has no manual "
            "calibration). Stop Streamlit with Ctrl+C and run it again."
        )
    source, screen = sidebar()
    frame = get_alerts(source)

    if screen == SCREENS[0]:
        screen_overview(frame, source)
    elif screen == SCREENS[1]:
        screen_queue(frame, source)
    elif screen == SCREENS[2]:
        screen_detail(frame, source)
    elif screen == SCREENS[3]:
        screen_rules(frame, source)
    elif screen == SCREENS[4]:
        screen_performance(frame, source)
    elif screen == SCREENS[5]:
        screen_vm(frame, source)
    elif screen == SCREENS[6]:
        screen_manual(frame, source)
    else:
        screen_method(frame, source)


if __name__ == "__main__":
    main()
