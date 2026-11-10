"""FastAPI service for the SentinelLOLBins alert scorer.

The service wraps ``src.alert_scoring.score_event`` as described in
``docs/alert_record_schema.md``. It does not train or retune anything; it
returns the alert record from the shared scorer.

Run:
    uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

import math
import os
import sys
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi import Body, FastAPI, HTTPException  # noqa: E402

from src.alert_scoring import ALERT_FIELDS, AlertScorer, score_event  # noqa: E402
from src.vm_schema_adapter import (  # noqa: E402
    MANUAL_FEATURE_DEFAULTS,
    MODEL_INPUT_COLUMNS,
    compute_row_features,
)

app = FastAPI(
    title="SentinelLOLBins Scoring API",
    version="1.0.0",
    description=(
        "Prototype LOLBin alert-triage API. Rules are evidence, not ground "
        "truth. Risk is a triage priority, not a verdict of compromise. This is "
        "not an EDR and makes no real-world performance claim."
    ),
)

_SCORER: Optional[AlertScorer] = None


def get_scorer() -> AlertScorer:
    global _SCORER
    if _SCORER is None:
        _SCORER = AlertScorer()
    return _SCORER


def _is_missing(value: Any) -> bool:
    return value is None or (isinstance(value, float) and math.isnan(value))


def _manual_row(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build model inputs for a hand-typed event missing the 57-column row.

    Uses the same Sysmon adapter as the dashboard, keeps explicit feature values
    if supplied, and fills only the 14 unrecoverable columns with the documented
    defaults. The raw model probability remains evidence; manual triage sets the
    band.
    """
    raw = dict(payload)
    for target, aliases in (
        ("Image", ("Image", "image", "process_name")),
        ("ParentImage", ("ParentImage", "parent_image", "parent_process")),
        ("CommandLine", ("CommandLine", "command_line")),
    ):
        if not raw.get(target):
            for key in aliases:
                if raw.get(key):
                    raw[target] = raw[key]
                    break
    command = str(raw.get("CommandLine") or "")
    if not command:
        return payload

    features = compute_row_features(raw, None)
    for key in MODEL_INPUT_COLUMNS:
        if not _is_missing(payload.get(key)):
            features[key] = payload[key]
    for key, default in MANUAL_FEATURE_DEFAULTS.items():
        if _is_missing(features.get(key)):
            features[key] = default

    features["CommandLine"] = command
    features["command_line"] = command
    for key in ("User", "scenario_id", "record_id"):
        if payload.get(key) is not None:
            features[key] = payload[key]
    return features


@app.get("/health")
def health() -> Dict[str, Any]:
    """Report whether the service is up and the saved model files loaded."""
    try:
        get_scorer()
        ready = True
    except Exception as exc:  # pragma: no cover - depends on local artifacts
        ready = False
        return {"status": "degraded", "model_ready": ready, "error": str(exc)}
    return {"status": "ok", "model_ready": ready}


@app.get("/schema")
def schema() -> Dict[str, List[str]]:
    """The exact alert-record field contract returned by POST /score."""
    return {"alert_fields": list(ALERT_FIELDS)}


@app.post("/score")
def score(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Score one event and return a single alert record.

    The body is the model-input row (dataset schema or raw Sysmon event). Pass
    ``xgb_proba`` (and optionally ``encoder_proba``) to score an already-scored
    event without re-running the model. Set ``manual`` to true for hand-typed
    events: missing model inputs are adapted from the raw event with documented
    defaults, then the transparent rules+indicator triage sets the band.
    """
    try:
        xgb_proba = payload.pop("xgb_proba", None)
        encoder_proba = payload.pop("encoder_proba", None)
        manual = bool(payload.pop("manual", False))
        if xgb_proba is not None:
            try:
                xgb_proba = float(xgb_proba)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=400, detail="xgb_proba must be numeric or null"
                ) from exc
        if manual and xgb_proba is None:
            payload = _manual_row(payload)
        return score_event(
            payload,
            xgb_proba=xgb_proba,
            encoder_proba=encoder_proba,
            scorer=get_scorer() if xgb_proba is None else None,
            manual=manual,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
