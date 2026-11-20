"""API tests for the score_event wrapper (Integration & quality)."""

import os
import sys
import unittest

from fastapi.testclient import TestClient

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from api.main import app  # noqa: E402
from src.alert_scoring import ALERT_FIELDS  # noqa: E402


def event(**overrides):
    row = {
        "record_id": "api_test_0001",
        "process_name": "powershell.exe",
        "parent_process": "explorer.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "User": "WIN11-TEST\\analyst",
        "xgb_proba": 0.95,
    }
    row.update(overrides)
    return row


class TestScoringApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertIn("model_ready", response.json())

    def test_schema_matches_contract(self):
        response = self.client.get("/schema")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["alert_fields"], list(ALERT_FIELDS))

    def test_score_returns_exact_contract(self):
        response = self.client.post("/score", json=event())
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(sorted(alert.keys()), sorted(ALERT_FIELDS))
        self.assertEqual(alert["decision"], "malicious")
        self.assertIn(alert["risk"], {"medium", "high"})

    def test_manual_normal_command_is_low(self):
        response = self.client.post(
            "/score",
            json=event(
                command_line="powershell.exe Get-Process",
                manual=True,
                xgb_proba=None,
            ),
        )
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(alert["decision"], "benign")
        self.assertEqual(alert["risk"], "low")

    def test_manual_malicious_command_is_high(self):
        response = self.client.post(
            "/score",
            json=event(
                command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
                manual=True,
                xgb_proba=None,
            ),
        )
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(alert["decision"], "malicious")
        self.assertEqual(alert["risk"], "high")
        self.assertTrue(alert["scoring_policy"].endswith("+manual_calibration"))

    def test_bad_payload_is_rejected(self):
        response = self.client.post("/score", json={"manual": True, "xgb_proba": "x"})
        self.assertEqual(response.status_code, 400)

    def test_bad_encoder_proba_is_rejected(self):
        response = self.client.post(
            "/score",
            json=event(encoder_proba="x"),
        )
        self.assertEqual(response.status_code, 400)

    def test_probability_below_range_is_rejected(self):
        for name in ("xgb_proba", "encoder_proba"):
            with self.subTest(name=name):
                response = self.client.post("/score", json=event(**{name: -0.1}))
                self.assertEqual(response.status_code, 400)

    def test_probability_above_range_is_rejected(self):
        for name in ("xgb_proba", "encoder_proba"):
            with self.subTest(name=name):
                response = self.client.post("/score", json=event(**{name: 1.2}))
                self.assertEqual(response.status_code, 400)

    def test_non_finite_probability_is_rejected(self):
        for name in ("xgb_proba", "encoder_proba"):
            for label, value in (
                ("nan", "nan"),
                ("inf", "inf"),
                ("-inf", "-inf"),
            ):
                with self.subTest(name=name, value=label):
                    response = self.client.post("/score", json=event(**{name: value}))
                    self.assertEqual(response.status_code, 400)

    def test_none_and_numeric_string_probabilities_are_accepted(self):
        response = self.client.post(
            "/score",
            json=event(manual=True, xgb_proba=None, encoder_proba=None),
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/score",
            json=event(xgb_proba="0.95", encoder_proba="0.4"),
        )
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(alert["model_version"]["function"], "fusion")
        self.assertEqual(alert["xgb_proba"], 0.95)
        self.assertEqual(alert["encoder_proba"], 0.4)

    def test_valid_encoder_proba_selects_fusion(self):
        response = self.client.post("/score", json=event(encoder_proba=0.4))
        self.assertEqual(response.status_code, 200)
        alert = response.json()
        self.assertEqual(alert["model_version"]["function"], "fusion")
        self.assertEqual(
            alert["model_version"]["checkpoint"], "fusion(xgb+securebert)"
        )


if __name__ == "__main__":
    unittest.main()
