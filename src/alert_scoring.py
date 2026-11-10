r"""Build fused alert records from a Windows process-creation event.

``score_event`` is the shared entry point used by the API and dashboard. It
combines three pieces of evidence:

* XGBoost, scored at the saved threshold in ``results/chosen_threshold.json``
  (0.55), or the validation-selected fusion when ``encoder_proba`` is supplied.
* The deterministic Sigma-style rules in ``rules/``.
* An optional SecureBERT probability from the caller.

The default decision is ``model OR high-severity rule``. When the model and a
rule disagree, both results stay in the record and ``review_required`` is set.

Hand-typed dashboard events (``manual=True``) are handled separately. They are
out of distribution for a model trained on synthetic data, so the risk band
comes from rules and command indicators instead of the raw probability alone.
A strong indicator or high/critical rule gives ``high``, a weak indicator gives
``medium``, and no indicator gives ``low``. The raw probability is still kept
as evidence.

This module does not retrain or modify any saved model. Label, technique, and
scenario fields are never used as features. Risk is a triage priority, not a
verdict that an endpoint was compromised.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import joblib
import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from rules.rule_engine import score_event as score_rules_event  # noqa: E402
from src.vm_schema_adapter import (  # noqa: E402
    MODEL_INPUT_COLUMNS,
    normalize_command_line,
)

MODEL_DIR = os.path.join(BASE, "results", "models")
RESULT_DIR = os.path.join(BASE, "results")
THRESHOLD_PATH = os.path.join(RESULT_DIR, "chosen_threshold.json")
FUSION_CONFIG_PATH = os.path.join(RESULT_DIR, "fusion_config.json")

HIGH_SEVERITIES = frozenset({"high", "critical"})
SEVERITY_POINTS = {"low": 10, "medium": 28, "high": 50, "critical": 60}
DEFAULT_POLICY = "model_or_high_severity_rule"
DISCLAIMER = (
    "Alert record from SentinelLOLBins. Risk is a triage priority, not a verdict "
    "of compromise. Rules are evidence, not ground truth. Prototype only; not an "
    "EDR replacement and not validated for enterprise deployment."
)

# Fields returned by score_event and the API.
ALERT_FIELDS = [
    "event_id",
    "record_id",
    "scenario_id",
    "scored_at",
    "process_name",
    "parent_process",
    "command_line",
    "user",
    "xgb_proba",
    "xgb_pred",
    "encoder_proba",
    "model_proba",
    "model_pred",
    "model_threshold",
    "rule_matched",
    "rule_ids",
    "rule_reasons",
    "rule_attack_ids",
    "rule_severity_max",
    "attack_techniques",
    "hybrid_score",
    "decision",
    "risk",
    "risk_score",
    "review_required",
    "evidence",
    "model_version",
    "scoring_policy",
    "disclaimer",
]


# Helpers.
def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if isinstance(row, Mapping):
        return row.get(key, default)
    if hasattr(row, "get"):
        return row.get(key, default)
    return default


def _has_key(row: Any, key: str) -> bool:
    if isinstance(row, Mapping):
        return key in row
    try:
        return key in row.index  # pandas Series exposes .index.
    except AttributeError:
        return False


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:  # NaN is not equal to itself.
        return ""
    return str(value).strip()


def _basename_lower(value: Any) -> str:
    text = _as_text(value).strip('"').replace("/", "\\")
    if not text:
        return ""
    return text.rsplit("\\", 1)[-1].lower()


def _native(value: Any) -> Any:
    """Convert numpy scalars and NaN values to JSON-safe types."""
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        value = float(value)
    if isinstance(value, float) and value != value:
        return None
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    return value


def _opt_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    if out != out:  # NaN is not equal to itself.
        return None
    return out


def _command_context(row: Any) -> Dict[str, str]:
    """Build the rule-engine context from a raw or adapted event."""
    command = _as_text(_row_get(row, "command_line", None))
    if not command:
        command = _as_text(_row_get(row, "CommandLine", None))
    normalized = _as_text(_row_get(row, "cmd_normalized", None))
    if not normalized:
        normalized = normalize_command_line(command)

    process = _as_text(_row_get(row, "process_name", None))
    if not process:
        process = _basename_lower(_row_get(row, "Image", None))
    parent = _as_text(_row_get(row, "parent_process", None))
    if not parent:
        parent = _basename_lower(_row_get(row, "ParentImage", None))

    return {
        "process_name": process.lower(),
        "parent_process": parent.lower(),
        "command_line": command,
        "cmd_normalized": normalized,
    }


def _risk_band(model_proba: float, severity: Optional[str], hybrid: bool) -> str:
    if not hybrid:
        return "low"
    if model_proba >= 0.85 or (severity or "").lower() in HIGH_SEVERITIES:
        return "high"
    return "medium"


def _risk_score(model_proba: float, severity: Optional[str], context_suspicious: bool) -> int:
    points = model_proba * 70.0
    points += SEVERITY_POINTS.get((severity or "").lower(), 0)
    if context_suspicious:
        points += 8
    return int(max(0, min(100, round(points))))


# Manual-event calibration. The saved model learned generator patterns (for
# example, almost every notepad/whoami template is malicious), so hand-typed
# benign commands are out of distribution. Manual events therefore use rules and
# indicators: strong or high/critical rule -> high; weak -> medium; none -> low.
# The raw probability stays in the record but does not set the band by itself.
MANUAL_HIGH_RISK_PROCESSES = frozenset({
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msbuild.exe", "cmstp.exe", "psexec.exe",
    "wscript.exe", "cscript.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "hh.exe", "pcalua.exe", "forfiles.exe",
})
MANUAL_STRONG_FLAGS = (
    "flag_enc", "flag_hidden_window", "flag_iex", "flag_downloadstring",
    "flag_invoke_expression", "flag_frombase64", "flag_regsvr32_script",
    "flag_mshta", "flag_certutil_urlcache", "flag_bitsadmin",
    "flag_schtasks_remote", "flag_wmic_remote", "flag_cmstp", "flag_mimikatz",
)
MANUAL_WEAK_FLAGS = ("flag_nop", "flag_ep_bypass")

_MANUAL_URL = re.compile(r"(?i)(?:https?|ftp)://[^\s\"'<>]+")
_MANUAL_UNC = re.compile(r"(?<![A-Za-z0-9])\\\\[^\s\"']+")
_MANUAL_B64 = re.compile(r"(?i)\b[a-z0-9+/]{32,}={0,2}\b")
_MANUAL_URI = re.compile(r"(?i)\b(?:javascript|vbscript|script):")
_MANUAL_PATH = re.compile(r"(?i)[a-z]:\\")
_MANUAL_SCRIPT = re.compile(
    r"(?i)\.(hta|jse?|vbe?|wsf|ps1|bat|cmd|scr|pif|lnk|sct|inf|dll|csproj|iso|img)\b")
_MANUAL_ACCOUNT_ADD = re.compile(
    r"(?i)\bnet(?:\.exe)?\s+(?:user|localgroup)\b[^\n]*(?:^|\s)/add\b")
_MANUAL_RECON = re.compile(
    r"(?i)\b(?:nltest|quser)\b|whoami\s+/(?:all|priv)\b|"
    r"net(?:\.exe)?\s+(?:group|localgroup|view)\b")
_MANUAL_RUN_KEY = re.compile(r"(?i)reg(?:\.exe)?\s+add\b[^\n]*\\run\b")
_MANUAL_SERVICE = re.compile(r"(?i)sc(?:\.exe)?\s+(?:create|config)\b")
_MANUAL_SCRIPT_EXEC = re.compile(r"(?i)\s-(?:file|f)\b")


def _stem(name: Any) -> str:
    text = str(name or "").strip().lower()
    return text[:-4] if text.endswith(".exe") else text


_MANUAL_HIGH_RISK_STEMS = frozenset(_stem(p) for p in MANUAL_HIGH_RISK_PROCESSES)


def _manual_effective_process(ctx: Dict[str, str]) -> str:
    """Process to triage on: the executable named in the command line when
    present, otherwise the declared process field. The command line wins so a
    normal command is not escalated by an unrelated process/parent field."""
    declared = (ctx.get("process_name") or "").strip().lower()
    command = (ctx.get("command_line") or "").strip().lstrip('"')
    token = command.split()[0] if command.split() else ""
    token = token.replace("/", "\\").rstrip("\"',;")
    base = token.rsplit("\\", 1)[-1].lower()
    exe_like = bool(re.search(
        r"(?i)\.(exe|com|bat|cmd|ps1|vbs|jse?|hta|msi|scr|pif)$", base))
    if exe_like:
        return base
    if _stem(base) in _MANUAL_HIGH_RISK_STEMS:
        return base
    if base and declared and _stem(base) == _stem(declared):
        return declared
    return declared


def _manual_triage(
    row: Any, ctx: Dict[str, str], severity: Optional[str]
) -> "tuple[List[str], List[str]]":
    """Return (strong, weak) human-readable indicators for a manual event."""
    strong: List[str] = []
    weak: List[str] = []
    command = ctx.get("command_line") or ""
    proc = _stem(_manual_effective_process(ctx))
    high_risk = proc in _MANUAL_HIGH_RISK_STEMS
    has_path = bool(_MANUAL_PATH.search(command))
    has_url = bool(_MANUAL_URL.search(command))

    for column in MANUAL_STRONG_FLAGS:
        if _row_get(row, column, 0) in (1, True):
            strong.append(column)
    for column in MANUAL_WEAK_FLAGS:
        if _row_get(row, column, 0) in (1, True):
            weak.append(column)

    if _MANUAL_URI.search(command):
        strong.append("javascript/vbscript URI")
    if _MANUAL_UNC.search(command):
        strong.append("UNC/remote path")
    if _MANUAL_ACCOUNT_ADD.search(command):
        strong.append("account creation/modification")
    if _MANUAL_RUN_KEY.search(command):
        strong.append("autorun registry persistence")
    if _MANUAL_RECON.search(command):
        weak.append("recon command")
    if _MANUAL_SERVICE.search(command):
        weak.append("service manipulation")
    if _MANUAL_SCRIPT.search(command) and _MANUAL_SCRIPT_EXEC.search(command):
        evasion = any(
            _row_get(row, flag, 0) in (1, True)
            for flag in ("flag_ep_bypass", "flag_nop", "flag_hidden_window")
        )
        if evasion:
            strong.append("script file execution with evasion flags")
        else:
            weak.append("script file execution")
    if has_url:
        if high_risk or "flag_iex" in strong or "flag_downloadstring" in strong:
            strong.append("remote URL")
        else:
            weak.append("URL in command")
    if _MANUAL_B64.search(command) and "flag_enc" not in strong:
        weak.append("long base64-like token")

    if high_risk:
        if has_path or _MANUAL_SCRIPT.search(command):
            strong.append("high-risk process with file path")
        else:
            weak.append("high-risk process")

    # process-specific abuse patterns (argument shape)
    if proc in {"rundll32", "regsvr32"} and has_path:
        strong.append("DLL/script proxy execution")
    if proc in {"cscript", "wscript", "mshta"} and _MANUAL_SCRIPT.search(command):
        strong.append("script host executing a script file")
    if proc == "msbuild" and has_path:
        strong.append("msbuild project execution")
    if proc == "certutil" and re.search(r"(?i)-(?:decode|encode|urlcache)\b", command):
        strong.append("certutil encode/decode")
    if proc == "wmic" and re.search(r"(?i)process\s+call\s+create|/node:", command):
        strong.append("remote process creation")
    if proc == "schtasks" and re.search(r"(?i)/create\b", command):
        if re.search(r"(?i)/create\b[^\n]*(?:powershell|cmd|http|\\\\|-enc\b)",
                     command):
            strong.append("scheduled task launch")
        else:
            weak.append("scheduled task creation")

    # parent context alone is only weak; a malicious command still scores high
    # from its own indicators.
    if _row_get(row, "parent_child_suspicious", 0) in (1, True):
        weak.append("office/script parent -> shell")
    if (severity or "").lower() in {"medium"}:
        weak.append(f"rule severity {severity}")

    # de-duplicate while preserving order
    strong = list(dict.fromkeys(strong))
    weak = [w for w in dict.fromkeys(weak) if w not in strong]
    return strong, weak


# Scorer.
class AlertScorer:
    """Loads the frozen artifacts once and produces alert records."""

    def __init__(
        self,
        model_dir: str = MODEL_DIR,
        threshold_path: str = THRESHOLD_PATH,
        fusion_config_path: str = FUSION_CONFIG_PATH,
        policy: str = DEFAULT_POLICY,
    ) -> None:
        self.model_dir = model_dir
        self.threshold_path = threshold_path
        self.fusion_config_path = fusion_config_path
        self.policy = policy
        self._pre = None
        self._model = None
        self._threshold: Optional[float] = None
        self._fusion: Optional[Dict[str, float]] = None

    # Load the model only when it is needed, so rule-only use still works.
    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        pre_path = os.path.join(self.model_dir, "preprocessor.joblib")
        model_path = os.path.join(self.model_dir, "xgb_baseline.joblib")
        if not os.path.exists(pre_path) or not os.path.exists(model_path):
            raise FileNotFoundError(
                "frozen model artifacts are missing; expected "
                f"{pre_path} and {model_path}. Provide xgb_proba explicitly for "
                "rule-only alert records."
            )
        self._pre = joblib.load(pre_path)
        self._model = joblib.load(model_path)

    def _ensure_threshold(self) -> float:
        if self._threshold is not None:
            return self._threshold
        if not os.path.exists(self.threshold_path):
            raise FileNotFoundError(
                f"missing {self.threshold_path}; cannot pin the validation-selected threshold"
            )
        with open(self.threshold_path) as f:
            self._threshold = float(json.load(f)["threshold"])
        return self._threshold

    def _ensure_fusion(self) -> Optional[Dict[str, float]]:
        if self._fusion is not None:
            return self._fusion
        if not os.path.exists(self.fusion_config_path):
            return None
        try:
            with open(self.fusion_config_path) as f:
                cfg = json.load(f)
            self._fusion = {
                "w_xgb": float(cfg["w_xgb"]),
                "w_encoder": float(cfg["w_encoder"]),
                "threshold": float(cfg["threshold"]),
            }
        except (KeyError, ValueError, TypeError):
            self._fusion = None
        return self._fusion

    def _xgb_proba(self, row: Any) -> float:
        missing = [c for c in MODEL_INPUT_COLUMNS if not _has_key(row, c)]
        if missing:
            raise ValueError(
                "row is missing model-input columns required for XGBoost scoring: "
                f"{missing}. Either adapt the event with src/vm_schema_adapter.py "
                "or pass xgb_proba explicitly."
            )
        self._ensure_model()
        frame = pd.DataFrame([{c: _row_get(row, c) for c in MODEL_INPUT_COLUMNS}])
        return float(self._model.predict_proba(self._pre.transform(frame))[:, 1][0])

    def score(
        self,
        row: Any,
        xgb_proba: Optional[float] = None,
        encoder_proba: Optional[float] = None,
        scored_at: Optional[str] = None,
        manual: bool = False,
    ) -> Dict[str, Any]:
        ctx = _command_context(row)

        p_xgb = _opt_float(xgb_proba)
        if p_xgb is None:
            p_xgb = self._xgb_proba(row)

        p_enc = _opt_float(encoder_proba)
        fusion = self._ensure_fusion() if p_enc is not None else None
        if p_enc is not None and fusion is not None:
            model_proba = fusion["w_xgb"] * p_xgb + fusion["w_encoder"] * p_enc
            model_threshold = fusion["threshold"]
            fn = "fusion"
        else:
            model_proba = p_xgb
            model_threshold = self._ensure_threshold()
            fn = "xgboost_baseline"

        model_pred = int(model_proba >= model_threshold)

        rule = score_rules_event(ctx)
        severity = rule.get("severity_max")
        rule_ids = list(rule.get("matched_rule_ids") or [])
        rule_reasons = list(rule.get("reasons") or [])
        attack_ids: List[str] = []
        for aid in rule.get("attack_ids") or []:
            aid = str(aid).strip()
            if aid and aid not in attack_ids:
                attack_ids.append(aid)
        rule_high = (severity or "").lower() in HIGH_SEVERITIES

        raw_model_pred = int(model_pred)
        manual_band: Optional[str] = None
        if manual:
            strong, weak = _manual_triage(row, ctx, severity)
            if rule_high or strong:
                hybrid = 1
                manual_band = "high"
            elif weak:
                hybrid = 1
                manual_band = "medium"
            else:
                hybrid = 0
                manual_band = "low"
            suppressed = bool(raw_model_pred) and not hybrid
        else:
            strong, weak = [], []
            hybrid = int(bool(raw_model_pred) or bool(rule_high))
            suppressed = False
        decision = "malicious" if hybrid else "benign"
        context_suspicious = bool(_row_get(row, "parent_child_suspicious", 0) in (1, True))
        if manual:
            risk = manual_band
            risk_score = {"high": 90, "medium": 60, "low": 15}[manual_band]
        else:
            risk = _risk_band(model_proba, severity, bool(hybrid))
            risk_score = _risk_score(model_proba, severity, context_suspicious)

        rule_matched = bool(rule.get("matched_any"))
        review_required = bool(rule_matched != bool(raw_model_pred)) or (
            suppressed or not ctx["parent_process"]
        )

        evidence: List[str] = []
        evidence.append(
            f"{fn} probability {model_proba:.3f} "
            f"(threshold {model_threshold:.2f}) -> model_pred={model_pred}"
        )
        if manual:
            evidence.append(
                "manual calibration: hand-typed events are out-of-distribution for "
                "the frozen model, so the band uses transparent rules+indicator triage"
            )
            if strong:
                evidence.append("manual triage strong indicator(s): " + ", ".join(strong))
            if weak:
                evidence.append("manual triage weak indicator(s): " + ", ".join(weak))
            if not strong and not weak:
                evidence.append(
                    "manual triage: no rule or concrete indicator; the raw model "
                    "score is retained as evidence but does not set the band"
                )
            if suppressed:
                evidence.append(
                    f"manual triage: raw model alert (proba {model_proba:.3f}) was "
                    f"not corroborated; banded {manual_band} and kept for review"
                )
        if p_enc is not None:
            evidence.append(f"SecureBERT probability {p_enc:.3f} (frozen encoder head)")
        if rule_matched:
            for rid, reason in zip(rule_ids, rule_reasons):
                evidence.append(f"rule {rid}: {reason}")
            evidence.append(f"rule severity_max={severity}")
        else:
            evidence.append("no rule matched")
        if ctx["parent_process"]:
            evidence.append(
                f"context: {ctx['process_name'] or '<unknown>'} <- {ctx['parent_process']}"
            )
        else:
            evidence.append("context: parent process unavailable (review)")

        record_id = _as_text(_row_get(row, "record_id", None))
        event_id = record_id or _as_text(_row_get(row, "event_id", None))
        if not event_id:
            event_id = _as_text(_row_get(row, "UtcTime", None)) or "event"

        alert = {
            "event_id": event_id,
            "record_id": record_id,
            "scenario_id": _as_text(_row_get(row, "scenario_id", None)) or None,
            "scored_at": scored_at
            or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "process_name": ctx["process_name"],
            "parent_process": ctx["parent_process"],
            "command_line": ctx["command_line"],
            "user": _as_text(_row_get(row, "User", None)) or None,
            "xgb_proba": round(float(p_xgb), 6),
            "xgb_pred": int(p_xgb >= self._ensure_threshold()),
            "encoder_proba": (round(float(p_enc), 6) if p_enc is not None else None),
            "model_proba": round(float(model_proba), 6),
            "model_pred": model_pred,
            "model_threshold": round(float(model_threshold), 6),
            "rule_matched": rule_matched,
            "rule_ids": rule_ids,
            "rule_reasons": rule_reasons,
            "rule_attack_ids": attack_ids,
            "rule_severity_max": severity,
            "attack_techniques": attack_ids,
            "hybrid_score": int(hybrid),
            "decision": decision,
            "risk": risk,
            "risk_score": int(risk_score),
            "review_required": review_required,
            "evidence": evidence,
            "model_version": {
                "function": fn,
                "checkpoint": "xgboost_baseline" if fn == "xgboost_baseline"
                else "fusion(xgb+securebert)",
                "threshold": round(float(model_threshold), 6),
                "rule_engine": "rules/ (deterministic Sigma-style)",
            },
            "scoring_policy": f"{self.policy}+manual_calibration" if manual
            else self.policy,
            "disclaimer": DISCLAIMER,
        }
        return {key: _native(alert[key]) for key in ALERT_FIELDS}

    def score_dataframe(
        self,
        df: pd.DataFrame,
        proba_col: Optional[str] = None,
        encoder_proba_col: Optional[str] = None,
        label_col: Optional[str] = None,
        per_outcome: Optional[int] = None,
    ) -> pd.DataFrame:
        """Score every row; optional stored-probability and demo-sampling modes."""
        if proba_col and proba_col not in df.columns:
            raise ValueError(f"proba_col {proba_col!r} not in dataframe")
        if encoder_proba_col and encoder_proba_col not in df.columns:
            raise ValueError(f"encoder_proba_col {encoder_proba_col!r} not in dataframe")
        if label_col and label_col not in df.columns:
            raise ValueError(f"label_col {label_col!r} not in dataframe")

        rows = []
        for _, row in df.iterrows():
            p = _row_get(row, proba_col) if proba_col else None
            pe = _row_get(row, encoder_proba_col) if encoder_proba_col else None
            rows.append(self.score(row, xgb_proba=p, encoder_proba=pe))
        out = pd.DataFrame(rows, columns=ALERT_FIELDS)

        if label_col:
            out["_true"] = pd.to_numeric(df[label_col], errors="coerce").values

        if per_outcome and per_outcome > 0 and "_true" in out.columns:
            out["_outcome"] = np.where(
                (out["_true"] == 1) & (out["hybrid_score"] == 1), "TP",
                np.where((out["_true"] == 0) & (out["hybrid_score"] == 1), "FP",
                         np.where((out["_true"] == 1) & (out["hybrid_score"] == 0), "FN",
                                  "TN")))
            out = out.groupby("_outcome", group_keys=False).head(per_outcome)
        return out.reset_index(drop=True)


# Module-level contract used by the API and dashboard.
_DEFAULT_SCORER: Optional[AlertScorer] = None


def get_default_scorer() -> AlertScorer:
    global _DEFAULT_SCORER
    if _DEFAULT_SCORER is None:
        _DEFAULT_SCORER = AlertScorer()
    return _DEFAULT_SCORER


def score_event(
    row: Any,
    xgb_proba: Optional[float] = None,
    encoder_proba: Optional[float] = None,
    scorer: Optional[AlertScorer] = None,
    manual: bool = False,
) -> Dict[str, Any]:
    """Contract used by the API/dashboard: one event -> one alert record.

    ``row`` may be a dict / pandas Series carrying either the 57 model-input
    columns (XGBoost is run automatically) or a precomputed probability via
    ``xgb_proba``.  The returned dict always has exactly ``ALERT_FIELDS`` keys.

    ``manual=True`` applies the out-of-distribution calibration for hand-typed
    events (rules-first triage; model-only alerts need a concrete indicator).
    """
    return (scorer or get_default_scorer()).score(
        row, xgb_proba=xgb_proba, encoder_proba=encoder_proba, manual=manual
    )


def score_dataframe(
    df: pd.DataFrame,
    proba_col: Optional[str] = None,
    encoder_proba_col: Optional[str] = None,
    label_col: Optional[str] = None,
    per_outcome: Optional[int] = None,
    scorer: Optional[AlertScorer] = None,
) -> pd.DataFrame:
    return (scorer or get_default_scorer()).score_dataframe(
        df,
        proba_col=proba_col,
        encoder_proba_col=encoder_proba_col,
        label_col=label_col,
        per_outcome=per_outcome,
    )


# CLI.
def _load_input(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise SystemExit(f"input not found: {path}")
    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Produce fused SentinelLOLBins alert records.")
    ap.add_argument("--input", required=True, help="adapted parquet or event csv")
    ap.add_argument("--out-dir", default=RESULT_DIR)
    ap.add_argument("--prefix", default="sample_alerts")
    ap.add_argument("--proba-col", default=None,
                    help="use an existing probability column instead of running XGBoost")
    ap.add_argument("--encoder-proba-col", default=None)
    ap.add_argument("--label-col", default=None,
                    help="carried only into the optional demo meta file, never scored")
    ap.add_argument("--per-outcome", type=int, default=None,
                    help="balanced demo sample: keep this many TP/FP/FN/TN rows")
    args = ap.parse_args()

    df = _load_input(args.input)
    scorer = AlertScorer()
    alerts = scorer.score_dataframe(
        df,
        proba_col=args.proba_col,
        encoder_proba_col=args.encoder_proba_col,
        label_col=args.label_col,
        per_outcome=args.per_outcome,
    )

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, f"{args.prefix}.csv")
    json_path = os.path.join(args.out_dir, f"{args.prefix}.json")

    exports = alerts.drop(columns=[c for c in ("_true", "_outcome") if c in alerts.columns])
    exports.to_csv(csv_path, index=False)
    records = [
        {k: _native(v) for k, v in rec.items()}
        for rec in exports.to_dict(orient="records")
    ]
    with open(json_path, "w") as f:
        json.dump(records, f, indent=2)

    if "_true" in alerts.columns:
        meta_cols = ["event_id", "record_id", "scenario_id", "_true"]
        if "_outcome" in alerts.columns:
            meta_cols.append("_outcome")
        meta = alerts[[c for c in meta_cols if c in alerts.columns]].rename(
            columns={"_true": "expected_label", "_outcome": "outcome"}
        )
        meta_path = os.path.join(args.out_dir, f"{args.prefix}_meta.csv")
        meta.to_csv(meta_path, index=False)
        print(f"wrote {meta_path}")

    print(f"scored {len(exports)} events -> {csv_path}")
    print(f"wrote {json_path}")
    print(exports["risk"].value_counts().to_dict())


if __name__ == "__main__":
    main()
