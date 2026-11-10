import tempfile
import unittest
from pathlib import Path
from hexforge.artifacts import load_export, normalize, timeline

class ArtifactTests(unittest.TestCase):
    def test_prefetch_and_amcache_distinction(self):
        rows = [
            {"source":"amcache","artifact_id":"A1","file_path":"C:/sample.exe","observed_time_utc":"2026-11-10T12:00:00Z"},
            {"source":"prefetch","artifact_id":"P1","file_path":"C:/sample.exe","observed_time_utc":"2026-11-10T11:00:00Z"}]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"export.csv"
            p.write_text("source,artifact_id,file_path,observed_time_utc\n"+ "\n".join(",".join(x.values()) for x in rows)+"\n",encoding="utf-8")
            result=load_export(p)
            self.assertEqual(result["record_count"],2)
            t=timeline(result)
            self.assertEqual(t["events"][0]["source"],"prefetch")
            self.assertFalse(t["execution_confirmed"])
            self.assertEqual(t["events"][1]["evidence_class"],"presence_or_inventory")
    def test_naive_time_rejected(self):
        with self.assertRaisesRegex(ValueError,"zona horaria"):
            normalize({"source":"amcache","artifact_id":"a","file_path":"x","observed_time_utc":"2026-11-10T12:00:00"},2)
    def test_invalid_amcache_execution_claim(self):
        with self.assertRaises(ValueError):
            normalize({"source":"amcache","artifact_id":"a","file_path":"x","observed_time_utc":"2026-11-10T12:00:00Z","event_type":"execution_indicator"},2)
    def test_invalid_hash(self):
        with self.assertRaises(ValueError):
            normalize({"source":"prefetch","artifact_id":"a","file_path":"x","observed_time_utc":"2026-11-10T12:00:00Z","sha256":"bad"},2)
    def test_missing_headers(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.csv";p.write_text("source,artifact_id\nprefetch,a\n")
            with self.assertRaises(ValueError):load_export(p)
    def test_source_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"empty.csv";p.write_text("source,artifact_id,file_path,observed_time_utc\n")
            r=load_export(p)
            import hashlib
            self.assertEqual(r["source_sha256"],hashlib.sha256(p.read_bytes()).hexdigest())
