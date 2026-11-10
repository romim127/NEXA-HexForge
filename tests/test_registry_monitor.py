import json
import tempfile
import unittest
from pathlib import Path
from hexforge.registry_monitor import classify_registry_event, analyze_export

class RegistryMonitorTests(unittest.TestCase):
    def test_run_key_review_not_proof(self):
        event={"event_id":13,"target_object":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo"}
        result=classify_registry_event(event)
        self.assertEqual(result["assessment"],"review")
        self.assertFalse(result["persistence_confirmed"])
    def test_regular_key(self):
        result=classify_registry_event({"event_id":12,"target_object":"HKCU\\Software\\Example"})
        self.assertEqual(result["assessment"],"informational")
    def test_invalid_id(self):
        with self.assertRaises(ValueError):
            classify_registry_event({"event_id":1,"target_object":"HKCU\\Software\\Example"})
    def test_export(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.json"
            p.write_text(json.dumps([{"event_id":14,"target_object":"HKLM\\Software\\Example"}]))
            result=analyze_export(p)
            self.assertEqual(result["count"],1)
            self.assertFalse(result["live_monitoring"])
