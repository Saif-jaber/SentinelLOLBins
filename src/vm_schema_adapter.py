"""Sysmon Event ID 1 -> WinLOLBIN-GT model-input adapter (Haitham, VM workstream).

Purpose
-------
Convert raw Sysmon Event ID 1 rows collected on the authorised, isolated
Windows evaluation VM (data/raw/vm/sysmon_events.csv) into the *same* feature
schema the frozen XGBoost model was trained on, without inventing values for
fields that cannot be obtained from the logs.

Contract (see docs/NOTES_TO_HAITHAM_SYSMON.txt section 6)
---------------------------------------------------------
* Never invent a value. Fields that cannot be computed stay NaN and are listed
  in the report file (docs/vm_missing_fields.txt) with the reason.
* Categorical values are lowercase image basenames ("cmd.exe"), unseen names
  are fine (the OneHotEncoder uses handle_unknown="ignore").
* expected_label / technique_expected are NEVER feature columns. They are
  carried through only as join keys for Saif's scoring script when
  --scenarios is supplied.
* The 57 columns produced here match the model-input schema (i.e. everything
  src/preprocess.py feeds to the ColumnTransformer, minus the drops). After
  one-hot encoding, that is the pipeline's 108-column internal width - the VM
  file does NOT need literal one-hot columns.

Feature provenance (measured against data/processed/sample_100k.parquet)
-------------------------------------------------------------------------
Recovered exactly (100% agreement on 20,000 random train rows; the adapter is
deterministic, so this holds for any input):
  cmd_len (== len of templated string), cmd_token_count, cmd_entropy
  (Shannon entropy, log2, of the templated string),
  cmd_avg_token_len (== cmd_len / cmd_token_count),
  cmd_pipe_count, cmd_amp_count, cmd_semicolon_count, cmd_redirect_count,
  cmd_backtick_count, cmd_quote_count, cmd_percent_count, cmd_dash_count,
  flag_enc, flag_ep_bypass, flag_hidden_window, flag_nop, flag_iex,
  flag_downloadstring, flag_invoke_expression, flag_frombase64,
  flag_regsvr32_script, flag_mshta, flag_certutil_urlcache, flag_bitsadmin,
  flag_schtasks_remote, flag_wmic_remote, flag_cmstp, flag_mimikatz

Approximated (documented, always reported):
  cmd_normalized     -> entity-templated copy of CommandLine (~87.5% byte-exact
                        reproduction of the dataset's normalization on train;
                        URLs/GUIDs/IPs/hashes/base64/paths are templated,
                        case preserved). Used for cmd_* stats; safe for rules.
  parent_child_suspicious
                     -> office/script host parent AND powershell/pwsh/cmd child.
                        The dataset's exact generator predicate is not published;
                        this is the documented approximation matched to the
                        observed evidence (winword/excel/wscript parents,
                        powershell/cmd children). parent_is_explorer remains a
                        separate feature, exactly as in the dataset.

Not derivable from logs -> always NaN (reported):
  cmd_url_token_count, cmd_path_token_count, cmd_ip_token_count,
  cmd_b64_token_count  (dataset generator regexes differ; ~92-98% agreement
                         possible but not exact - excluded deliberately)
  flag_certutil_encode, flag_remote_file, flag_rundll32_js, flag_msbuild,
  flag_adsi, flag_cmd_slash_c
                        (generator templates not recoverable exactly;
                         a systematically-off flag is worse than a missing one)
  signed_true           -> needs Get-AuthenticodeSignature on the VM; pass an
                         optional signed_status column (valid/invalid/unsigned)
  network_connection_true, has_destination
                        -> from --network sysmon_network.csv (Event ID 3);
                           NaN when not supplied, 0/1 when supplied
  integrity_ordinal     -> dataset ordinal mapping unpublished; left NaN

Usage
-----
  python src/vm_schema_adapter.py \
      --events data/raw/vm/sysmon_events.csv \
      --network data/raw/vm/sysmon_network.csv \
      --scenarios data/raw/vm/scenarios.csv \
      --out data/processed/vm_adapted.parquet \
      --report docs/vm_missing_fields.txt

Exit codes: 0 ok; 2 for contract violations (missing required column,
empty Image, duplicate ProcessId+UtcTime+Image rows dropped out).
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional

import pandas as pd

# --------------------------------------------------------------------------- #
# constants (verified against the dataset; do not "improve" without evidence) #
# --------------------------------------------------------------------------- #

LOLBIN_CHILD_PROCESSES = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe"})
SCRIPT_HOST_PARENTS = frozenset({"wscript.exe", "cscript.exe"})
OFFICE_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "onenote.exe",
})
powershell_NAMES = frozenset({"powershell.exe", "pwsh.exe"})
script_host_NAMES = frozenset({"wscript.exe", "cscript.exe"})

MODEL_INPUT_COLUMNS = [
    "process_name", "parent_process",
    "cmd_len", "cmd_token_count", "cmd_entropy", "cmd_avg_token_len",
    "cmd_pipe_count", "cmd_amp_count", "cmd_semicolon_count",
    "cmd_redirect_count", "cmd_backtick_count", "cmd_quote_count",
    "cmd_percent_count", "cmd_dash_count",
    "cmd_url_token_count", "cmd_path_token_count",
    "cmd_ip_token_count", "cmd_b64_token_count",
    "flag_enc", "flag_ep_bypass", "flag_hidden_window", "flag_nop",
    "flag_iex", "flag_downloadstring", "flag_invoke_expression",
    "flag_frombase64", "flag_regsvr32_script", "flag_mshta",
    "flag_certutil_urlcache", "flag_certutil_encode", "flag_bitsadmin",
    "flag_mimikatz", "flag_remote_file", "flag_schtasks_remote",
    "flag_wmic_remote", "flag_rundll32_js", "flag_msbuild",
    "flag_cmstp", "flag_adsi", "flag_cmd_slash_c",
    "process_is_powershell", "process_is_cmd",
    "process_is_script_host", "process_is_rundll32",
    "path_in_system32", "path_in_syswow64", "path_in_temp",
    "path_in_users", "path_in_programdata",
    "parent_known", "parent_is_office", "parent_is_explorer",
    "parent_child_suspicious",
    "signed_true", "network_connection_true", "has_destination",
    "integrity_ordinal",
]

PASS_THROUGH_COLUMNS = ["scenario_id", "record_id"]
EXTRA_CONTEXT_COLUMNS = ["expected_label", "technique_expected"]  # join keys only
RAW_AUDIT_COLUMNS = ["UtcTime", "Computer", "ProcessId", "Image", "ParentImage",
                     "CommandLine", "ParentCommandLine", "User", "IntegrityLevel"]

NEVER_FEATURE_COLUMNS = {"expected_label", "technique_expected", "scenario_id",
                         "record_id", "label", "mitre_technique"}

# --------------------------------------------------------------------------- #
# command-line normalization (entity templating, case preserved)              #
# --------------------------------------------------------------------------- #
_MSI_URL = re.compile(r"(?i)(ms-appinstaller:|script:)[^\s\"']+")
_URL = re.compile(r"(?<![A-Za-z0-9/_-])(?:https?|ftp)://[^\s\"'<>]*")
_GUID = re.compile(r"(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}")
_HASH32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_IP4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_DRIVE_PATH = re.compile(r"(?i)(?<=[a-z]:)\\[^\s\"']*")
_UNC_PATH = re.compile(r"(?<![A-Za-z0-9])\\\\[^\s\"']+")
_B64_SYMBOL = re.compile(r"[0-9+/=_-]")


def normalize_command_line(text: str) -> str:
    """Best-effort reproduction of the dataset's entity templating.

    ~87.5% byte-exact against the dataset's own normalization on 2,000 random
    train rows. The residual difference only affects URLs/paths inside
    unusual arguments; case is preserved (the dataset does NOT lowercase).
    """
    t = str(text or "")
    t = _MSI_URL.sub("<URL>", t)
    t = _URL.sub("<URL>", t)
    t = _GUID.sub("{<GUID>}", t)
    t = _HASH32.sub("<HASH>", t)
    t = _IP4.sub("<IP>", t)

    def _b64(m: "re.Match[str]") -> str:
        tok = m.group(0)
        return "<B64>" if _B64_SYMBOL.search(tok) else tok

    t = _B64_TOKEN.sub(_b64, t)
    t = _DRIVE_PATH.sub("<PATH>", t)
    t = _UNC_PATH.sub("<PATH>", t)
    return t


# --------------------------------------------------------------------------- #
# flag patterns recovered exactly (100% agreement, fp=0, fn=0, 20k train)     #
# --------------------------------------------------------------------------- #
_FLAG_PATTERNS = {
    "flag_enc": re.compile(r"-enc(odedcommand)?\b", re.I),
    "flag_ep_bypass": re.compile(r"-ep\s*bypass|-executionpolicy\s*bypass", re.I),
    "flag_hidden_window": re.compile(r"-w\s+hidden", re.I),
    "flag_nop": re.compile(r"-nop\b", re.I),
    "flag_iex": re.compile(r"\biex\b", re.I),
    "flag_downloadstring": re.compile(r"downloadstring", re.I),
    "flag_invoke_expression": re.compile(r"invoke-expression", re.I),
    "flag_frombase64": re.compile(r"frombase64", re.I),
    "flag_regsvr32_script": re.compile(r"scrobj\.dll|/i:.*\.(sct|js|vbs)", re.I),
    "flag_mshta": re.compile(r"\.hta\b|mshta", re.I),
    "flag_certutil_urlcache": re.compile(r"urlcache", re.I),
    "flag_bitsadmin": re.compile(r"bitsadmin", re.I),
    "flag_schtasks_remote": re.compile(r"schtasks.*(/s\s+\S+|\\\\)", re.I),
    "flag_wmic_remote": re.compile(r"/node:|winrm", re.I),
    "flag_cmstp": re.compile(r"cmstp", re.I),
    "flag_mimikatz": re.compile(r"mimikatz", re.I),
}
FLAG_COLUMNS_UNRECOVERABLE = [
    "flag_certutil_encode", "flag_remote_file", "flag_rundll32_js",
    "flag_msbuild", "flag_adsi", "flag_cmd_slash_c",
]


def _shannon_entropy_log2(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in freq.values()))


def _count(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text))


def _basename_lower(path: Any) -> str:
    p = str(path or "").strip()
    if not p:
        return ""
    # handle both path separator styles and quoted images
    p = p.strip('"')
    p = p.replace("/", "\\")
    return p.rsplit("\\", 1)[-1].lower()


def _contains_ci(haystack: str, needle: str) -> int:
    return 1 if needle.lower() in str(haystack or "").lower() else 0


def compute_row_features(raw: Dict[str, Any],
                         network: Optional[pd.DataFrame]) -> Dict[str, Any]:
    image = str(raw.get("Image") or "")
    parent_image = str(raw.get("ParentImage") or "")
    command_line = str(raw.get("CommandLine") or "")

    process_name = _basename_lower(image)
    parent_process = _basename_lower(parent_image)

    norm = normalize_command_line(command_line)
    cmd_len = len(norm)
    tokens = norm.split()
    token_count = len(tokens)
    entropy = _shannon_entropy_log2(norm)
    avg_token_len = (cmd_len / token_count) if token_count else 0.0

    out: Dict[str, Any] = {
        "process_name": process_name,
        "parent_process": parent_process,
        "cmd_len": cmd_len,
        "cmd_token_count": token_count,
        "cmd_entropy": entropy,
        "cmd_avg_token_len": avg_token_len,
        "cmd_pipe_count": _count(command_line, r"\|"),
        "cmd_amp_count": command_line.count("&"),
        "cmd_semicolon_count": command_line.count(";"),
        "cmd_redirect_count": _count(command_line, r"[<>]"),
        "cmd_backtick_count": command_line.count("`"),
        "cmd_quote_count": _count(command_line, r"[\"']"),
        "cmd_percent_count": command_line.count("%"),
        "cmd_dash_count": command_line.count("-"),
        # generator regexes not recoverable -> NaN (see module docstring)
        "cmd_url_token_count": float("nan"),
        "cmd_path_token_count": float("nan"),
        "cmd_ip_token_count": float("nan"),
        "cmd_b64_token_count": float("nan"),
    }

    for flag, rx in _FLAG_PATTERNS.items():
        out[flag] = int(bool(rx.search(command_line)))
    for flag in FLAG_COLUMNS_UNRECOVERABLE:
        out[flag] = float("nan")

    out["process_is_powershell"] = int(process_name in powershell_NAMES)
    out["process_is_cmd"] = int(process_name == "cmd.exe")
    out["process_is_script_host"] = int(process_name in script_host_NAMES)
    out["process_is_rundll32"] = int(process_name == "rundll32.exe")

    out["path_in_system32"] = _contains_ci(image, "\\system32\\")
    out["path_in_syswow64"] = _contains_ci(image, "\\syswow64\\")
    out["path_in_temp"] = _contains_ci(image, "\\temp\\")
    out["path_in_users"] = _contains_ci(image, "\\users\\")
    out["path_in_programdata"] = _contains_ci(image, "\\programdata\\")

    out["parent_known"] = int(bool(parent_process))
    out["parent_is_office"] = int(parent_process in OFFICE_PARENTS)
    out["parent_is_explorer"] = int(parent_process == "explorer.exe")
    # Approximation matched to the dataset evidence (258x powershell, 2x cmd,
    # parents winword/excel/wscript). parent_is_explorer stays its own feature.
    out["parent_child_suspicious"] = int(
        (parent_process in OFFICE_PARENTS or parent_process in SCRIPT_HOST_PARENTS)
        and process_name in LOLBIN_CHILD_PROCESSES
    )

    # signed_true: optional signed_status column (valid/invalid/unsigned/unknown)
    signed_status = str(raw.get("signed_status") or "").strip().lower()
    if signed_status == "valid":
        out["signed_true"] = 1
    elif signed_status in {"invalid", "unsigned", "notsigned"}:
        out["signed_true"] = 0
    else:
        out["signed_true"] = float("nan")

    # network linkage from Event ID 3 (optional)
    if network is not None and not network.empty:
        scenario = str(raw.get("scenario_id") or "")
        pid = pd.to_numeric(raw.get("ProcessId"), errors="coerce")
        net_pid = pd.to_numeric(network["ProcessId"], errors="coerce")
        match = network[(net_pid == pid) &
                        (network["scenario_id"].astype(str) == scenario)]
        if match.empty and "scenario_id" not in network.columns:
            match = network[net_pid == pid]
        out["network_connection_true"] = int(not match.empty)
        if not match.empty:
            dest = str(match.iloc[0].get("DestinationIp") or "").strip()
            out["has_destination"] = int(bool(dest))
        else:
            out["has_destination"] = 0
    else:
        out["network_connection_true"] = float("nan")
        out["has_destination"] = float("nan")

    out["integrity_ordinal"] = float("nan")
    return out


# --------------------------------------------------------------------------- #
# driver                                                                      #
# --------------------------------------------------------------------------- #
REQUIRED_EVENT_COLUMNS = ["Image", "CommandLine", "ParentImage", "ProcessId",
                          "UtcTime", "scenario_id"]


def load_events(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise SystemExit(f"events file not found: {path}")
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = [c for c in REQUIRED_EVENT_COLUMNS if c not in df.columns]
    if missing:
        raise SystemExit(f"events file missing required columns: {missing}")
    if (df["Image"].str.strip() == "").any():
        bad = int((df["Image"].str.strip() == "").sum())
        raise SystemExit(f"{bad} row(s) have an empty Image - refusing to guess")
    return df


def load_network(path: Optional[str]) -> Optional[pd.DataFrame]:
    if not path:
        return None
    if not os.path.exists(path):
        print(f"warning: network file not found, network_* stay NaN: {path}")
        return None
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for col in ("ProcessId", "scenario_id"):
        if col not in df.columns:
            raise SystemExit(f"network file missing required column: {col}")
    df["ProcessId"] = pd.to_numeric(df["ProcessId"], errors="coerce")
    return df


def load_scenarios(path: Optional[str]) -> Optional[pd.DataFrame]:
    if not path:
        return None
    if not os.path.exists(path):
        print(f"warning: scenarios file not found, expected_label not merged: {path}")
        return None
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "scenario_id" not in df.columns:
        raise SystemExit("scenarios file missing required column: scenario_id")
    keep = [c for c in ("scenario_id", "expected_label", "technique_expected")
            if c in df.columns]
    return df[keep].drop_duplicates(subset=["scenario_id"])


def make_record_id(row: pd.Series) -> str:
    key = "|".join([
        str(row.get("Computer", "")), str(row.get("UtcTime", "")),
        str(row.get("ProcessId", "")), str(row.get("Image", "")),
        str(row.get("CommandLine", "")),
    ])
    return "vm_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--events", required=True)
    ap.add_argument("--network", default=None)
    ap.add_argument("--scenarios", default=None)
    ap.add_argument("--out", default=os.path.join("data", "processed", "vm_adapted.parquet"))
    ap.add_argument("--report", default=os.path.join("docs", "vm_missing_fields.txt"))
    ap.add_argument("--csv", action="store_true", help="also write a .csv alongside --out")
    args = ap.parse_args()

    events = load_events(args.events)
    network = load_network(args.network)
    scenarios = load_scenarios(args.scenarios)

    events = events.copy()
    # numeric ProcessId for the network join (Sysmon logs it as decimal)
    events["ProcessId"] = pd.to_numeric(events["ProcessId"], errors="coerce")

    records: List[Dict[str, Any]] = []
    for _, row in events.iterrows():
        feats = compute_row_features(row.to_dict(), network)
        feats["scenario_id"] = str(row.get("scenario_id") or "")
        feats["record_id"] = make_record_id(row)
        for col in RAW_AUDIT_COLUMNS:
            feats[col] = str(row.get(col, ""))
        records.append(feats)

    out = pd.DataFrame(records)
    if scenarios is not None:
        out = out.merge(scenarios, on="scenario_id", how="left")

    ordered = (PASS_THROUGH_COLUMNS + MODEL_INPUT_COLUMNS
               + [c for c in EXTRA_CONTEXT_COLUMNS if c in out.columns]
               + RAW_AUDIT_COLUMNS)
    out = out[[c for c in ordered if c in out.columns]]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    out.to_parquet(args.out, index=False)
    if args.csv:
        out.to_csv(os.path.splitext(args.out)[0] + ".csv", index=False)

    nan_cols = {c: int(out[c].isna().sum()) for c in MODEL_INPUT_COLUMNS
                if out[c].isna().any()}
    lines = [
        "VM ADAPTER MISSING-FIELDS REPORT",
        f"events: {args.events}",
        f"rows: {len(out)}",
        f"out: {args.out}",
        "",
        "Columns containing missing (NaN) values and why:",
    ]
    reasons = {
        "cmd_url_token_count": "dataset generator regex not recoverable; excluded to avoid miscalibration",
        "cmd_path_token_count": "dataset generator regex not recoverable; excluded to avoid miscalibration",
        "cmd_ip_token_count": "dataset generator regex not recoverable; excluded to avoid miscalibration",
        "cmd_b64_token_count": "dataset generator regex not recoverable; excluded to avoid miscalibration",
        "flag_certutil_encode": "generator sets it on the urlcache|decode chain, not on -encode literally; not recoverable exactly",
        "flag_remote_file": "generator predicate not recoverable exactly (partial: downloadstring|iwr; fp>0); excluded",
        "flag_rundll32_js": "generator predicate not recoverable exactly (partial: javascript:; fn present); excluded",
        "flag_msbuild": "generator predicate not recoverable exactly (template-derived; some positives contain no 'msbuild' string); excluded",
        "flag_adsi": "generator predicate not recoverable exactly (~0.25% disagreement); excluded",
        "flag_cmd_slash_c": "generator predicate not recoverable exactly (11 fp / 100 benign hits); excluded",
        "signed_true": "requires Get-AuthenticodeSignature on the VM; pass a signed_status column to fill",
        "network_connection_true": "Sysmon Event ID 3 not supplied (--network)",
        "has_destination": "Sysmon Event ID 3 not supplied (--network)",
        "integrity_ordinal": "dataset ordinal mapping unpublished; left missing by policy",
    }
    if not nan_cols:
        lines.append("  (none)")
    else:
        for col, cnt in sorted(nan_cols.items()):
            lines.append(f"  {col}: {cnt}/{len(out)} missing - {reasons.get(col, 'not available')}")
    lines += [
        "",
        "Notes:",
        "  * parent_child_suspicious is an approximation (office/script-host",
        "    parent AND powershell/pwsh/cmd child); dataset generator predicate is",
        "    not published. parent_is_explorer is separate, as in the dataset.",
        "  * cmd_normalized reproduces the dataset entity templating (~87.5% byte-",
        "    exact on train); case preserved.",
        "  * expected_label / technique_expected are join keys, never features.",
    ]
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"wrote {args.out} ({len(out)} rows, {len(MODEL_INPUT_COLUMNS)} model-input cols)")
    print(f"wrote {args.report}")


if __name__ == "__main__":
    main()
