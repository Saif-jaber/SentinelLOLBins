r"""Deterministic, hand-written Sigma-style rule engine for SentinelLOLBins (E1).

The engine evaluates declarative LOLBin rules over a single process-creation
event (or a dataframe of events) and produces interpretable rule evidence:

    score_event(row: dict) -> dict
    score_dataframe(df) -> pd.DataFrame

Rules are loaded from the YAML files in ``rules/`` (one or more rules per
file).  A rule looks like:

    - id: RULE-PS-001
      title: PowerShell encoded command
      attack: T1059.001
      severity: high
      applies_to_process: [powershell.exe, pwsh.exe]
      conditions:
        any:
          - command_line_regex: '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'
      reason: "PowerShell used with an encoded payload"
      references:
        - https://attack.mitre.org/techniques/T1059/001/

Condition types (kept small and explainable):

    process_is:      exact image name match (value: string or list)
    parent_is:       exact parent image name match (value: string or list)
    command_line_regex: case-insensitive regex over command_line / cmd_normalized
    path_regex:      regex over command line or image path
    any / all / not: boolean composition (lists of sub-conditions)

``applies_to_process`` acts as an implicit AND gate on the event process name.

The engine is deterministic: no randomness, no I/O beyond loading rule files.
It only reads process_name, parent_process, command_line and cmd_normalized from
an event; label / technique / source / category fields are never consulted.
"""

import os
import re
from typing import Any, Dict, List, Optional

import yaml
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "rules")

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VALID_SEVERITIES = ("low", "medium", "high", "critical")
COMBINATOR_KEYS = ("any", "all", "not")

OUTPUT_COLUMNS = [
    "record_id",
    "matched_any",
    "n_rules_matched",
    "matched_rule_ids",
    "reasons",
    "attack_ids",
    "severity_max",
]

_LEAF_KEYS = ("process_is", "parent_is", "command_line_regex", "path_regex")

_pattern_cache: Dict[str, "re.Pattern"] = {}
_rules_cache: Optional[list] = None
_rules_cache_dir: Optional[str] = None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _as_text(value: Any) -> str:
    """Coerce an event field to a stripped string; NaN / None become ''."""
    if value is None:
        return ""
    if isinstance(value, float) and value != value:  # NaN
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()


def _norm_name(value: Any) -> str:
    """Lowercase image / parent name."""
    return _as_text(value).lower()


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [v for v in value if v is not None]
    return [value]


def _get_pattern(pattern: str) -> "re.Pattern":
    key = str(pattern)
    if key not in _pattern_cache:
        _pattern_cache[key] = re.compile(key, re.IGNORECASE)
    return _pattern_cache[key]


# --------------------------------------------------------------------------- #
# condition evaluation
# --------------------------------------------------------------------------- #
def _eval_leaf(key: str, value: Any, ctx: Dict[str, str]) -> bool:
    if key == "process_is":
        names = {str(n).strip().lower() for n in _as_list(value) if str(n).strip()}
        return ctx["process_name"] in names
    if key == "parent_is":
        names = {str(n).strip().lower() for n in _as_list(value) if str(n).strip()}
        return ctx["parent_process"] in names
    if key == "command_line_regex":
        patterns = [str(p) for p in _as_list(value)]
        for haystack in (ctx["command_line"], ctx["cmd_normalized"]):
            if not haystack:
                continue
            for pattern in patterns:
                if _get_pattern(pattern).search(haystack):
                    return True
        return False
    if key == "path_regex":
        patterns = [str(p) for p in _as_list(value)]
        haystacks = (
            ctx["command_line"],
            ctx["cmd_normalized"],
            ctx["process_name"],
            ctx["parent_process"],
        )
        for haystack in haystacks:
            if not haystack:
                continue
            for pattern in patterns:
                if _get_pattern(pattern).search(haystack):
                    return True
        return False
    return False


def _eval_condition(cond: Any, ctx: Dict[str, str]) -> bool:
    """Evaluate one condition node. Supports leaf ANDs and any/all/not."""
    if not isinstance(cond, dict):
        return False
    comb = [k for k in COMBINATOR_KEYS if k in cond]
    if comb:
        op = comb[0]
        subs = [s for s in (cond.get(op) or []) if isinstance(s, dict)]
        if op == "any":
            return any(_eval_condition(s, ctx) for s in subs)
        if op == "all":
            return all(_eval_condition(s, ctx) for s in subs)
        if op == "not":
            sub = subs[0] if subs else {}
            return not _eval_condition(sub, ctx)
        return False
    leaves = {k: cond[k] for k in _LEAF_KEYS if cond.get(k) is not None}
    if not leaves:
        return False
    return all(_eval_leaf(k, v, ctx) for k, v in leaves.items())


def _rule_applies(rule: Dict[str, Any], ctx: Dict[str, str]) -> bool:
    applies = rule.get("applies_to_process")
    if applies is None:
        return True
    names = {str(n).strip().lower() for n in _as_list(applies) if str(n).strip()}
    if not names:
        return True
    return ctx["process_name"] in names


def _rule_matches(rule: Dict[str, Any], ctx: Dict[str, str]) -> bool:
    conditions = rule.get("conditions")
    if conditions is None:
        return False
    if isinstance(conditions, dict):
        cond_nodes = [conditions]
    elif isinstance(conditions, list):
        cond_nodes = [c for c in conditions if isinstance(c, dict)]
    else:
        cond_nodes = []
    return any(_eval_condition(c, ctx) for c in cond_nodes)


# --------------------------------------------------------------------------- #
# rule loading / validation
# --------------------------------------------------------------------------- #
def _validate_rule(rule: Any) -> None:
    if not isinstance(rule, dict):
        raise ValueError("each rule must be a mapping")
    rid = rule.get("id") or "<unknown>"
    for key in ("id", "title", "attack", "severity", "reason", "conditions"):
        if rule.get(key) in (None, ""):
            raise ValueError(f"rule {rid} is missing required field '{key}'")
    sev = str(rule.get("severity")).strip().lower()
    if sev not in SEVERITY_RANK:
        raise ValueError(f"rule {rid} has invalid severity {rule.get('severity')!r}")


def load_rules(directory: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load all rules from ``rules/*.yml`` (sorted by filename)."""
    rules_dir = directory or RULES_DIR
    loaded: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(rules_dir)):
        if not (fname.endswith(".yml") or fname.endswith(".yaml")):
            continue
        path = os.path.join(rules_dir, fname)
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        if data is None:
            continue
        if isinstance(data, dict):
            data = [data]
        for rule in data:
            _validate_rule(rule)
            loaded.append(rule)
    return loaded


def get_rules(directory: Optional[str] = None) -> List[Dict[str, Any]]:
    global _rules_cache, _rules_cache_dir
    d = directory or RULES_DIR
    if _rules_cache is None or _rules_cache_dir != d:
        _rules_cache = load_rules(d)
        _rules_cache_dir = d
    return _rules_cache


def reset_rules_cache() -> None:
    global _rules_cache, _rules_cache_dir
    _rules_cache = None
    _rules_cache_dir = None


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
def score_event(row: Any) -> Dict[str, Any]:
    """Score one process-creation event.

    row: one event as a dict (or pandas Series) with at least
         process_name, parent_process, command_line, cmd_normalized.
    Returns:
        {
            "matched_any": bool,
            "matched_rule_ids": [rule ids],
            "reasons": [human readable reason, ...],
            "attack_ids": [attack ids, ...],
            "severity_max": "low" | "medium" | "high" | "critical" | None,
        }
    """
    if hasattr(row, "to_dict"):
        row = row.to_dict()
    elif not isinstance(row, dict):
        row = dict(row)

    ctx: Dict[str, str] = {
        "process_name": _norm_name(row.get("process_name")),
        "parent_process": _norm_name(row.get("parent_process")),
        "command_line": _as_text(row.get("command_line")),
        "cmd_normalized": _as_text(row.get("cmd_normalized")),
    }

    matched: List[Dict[str, Any]] = []
    for rule in get_rules():
        if not _rule_applies(rule, ctx):
            continue
        if not _rule_matches(rule, ctx):
            continue
        matched.append(rule)
    matched.sort(key=lambda r: str(r.get("id") or ""))

    attack_ids: List[str] = []
    for r in matched:
        for aid in _as_list(r.get("attack")):
            aid = str(aid).strip()
            if aid and aid not in attack_ids:
                attack_ids.append(aid)

    severity_max: Optional[str] = None
    best = 0
    for r in matched:
        sev = str(r.get("severity") or "low").strip().lower()
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > best:
            best = rank
            severity_max = sev

    return {
        "matched_any": len(matched) > 0,
        "matched_rule_ids": [str(r.get("id")) for r in matched],
        "reasons": [str(r.get("reason") or r.get("id") or "") for r in matched],
        "attack_ids": attack_ids,
        "severity_max": severity_max,
    }


def score_dataframe(df) -> pd.DataFrame:
    """Score a dataframe of events; one output row per input row, same order.

    Output columns (in order):
        record_id, matched_any, n_rules_matched, matched_rule_ids, reasons,
        attack_ids, severity_max
    """
    records = []
    for _, row in df.iterrows():
        res = score_event(row)
        records.append({
            "record_id": _as_text(row.get("record_id")),
            "matched_any": 1 if res["matched_any"] else 0,
            "n_rules_matched": len(res["matched_rule_ids"]),
            "matched_rule_ids": ";".join(res["matched_rule_ids"]),
            "reasons": ";".join(res["reasons"]),
            "attack_ids": ";".join(res["attack_ids"]),
            "severity_max": res["severity_max"],
        })
    out = pd.DataFrame(records, columns=OUTPUT_COLUMNS)
    # normalize severity_max to str | None (pandas may coerce None -> NaN)
    sev_values = [
        None if (v is None or (isinstance(v, float) and v != v)) else str(v)
        for v in out["severity_max"].tolist()
    ]
    out["severity_max"] = pd.Series(sev_values, index=out.index, dtype=object)
    return out
