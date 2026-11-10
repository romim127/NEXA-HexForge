import copy
import tempfile
import unittest
from pathlib import Path
from hexforge.academy import hex_to_binary, binary_to_hex
from hexforge.custody import register_evidence, append_event, verify_chain, verify_evidence, save_new, load_record

class AcademyTests(unittest.TestCase):
    def test_af(self):
        r=hex_to_binary("AF")
        self.assertEqual(r["binary"],"10101111")
        self.assertEqual(r["decimal"],175)
        self.assertEqual([x["contribution"] for x in r["steps"]],[160,15])
    def test_leading_zero(self):
        self.assertEqual(hex_to_binary("0x0F")["binary"],"00001111")
    def test_inverse(self):
        self.assertEqual(binary_to_hex("10101111")["hex"],"AF")
        self.assertEqual(binary_to_hex("101")["hex"],"5")
    def test_reject_invalid(self):
        for value in ("", "GG", "F"*17):
            with self.subTest(value=value), self.assertRaises(ValueError):hex_to_binary(value)

class CustodyTests(unittest.TestCase):
    def test_chain_and_file_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"evidence.bin";p.write_bytes(b"forensic fixture")
            record=register_evidence("CASE-001",p,"Analyst")
            record=append_event(record,"examined","Analyst","Static inspection","2026-11-10T12:00:00Z")
            self.assertTrue(verify_chain(record)["chain_valid"])
            self.assertTrue(verify_evidence(record,p)["evidence_hash_matches"])
            report=Path(d)/"custody.json";save_new(record,report)
            self.assertEqual(load_record(report)["events"][1]["action"],"examined")
            with self.assertRaises(FileExistsError):save_new(record,report)
            p.write_bytes(b"modified fixture")
            self.assertFalse(verify_evidence(record,p)["evidence_hash_matches"])
    def test_detect_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"evidence";p.write_bytes(b"abc")
            record=register_evidence("E-1",p,"Analyst")
            modified=copy.deepcopy(record)
            modified["events"][0]["actor"]="Impostor"
            with self.assertRaisesRegex(ValueError,"Hash de actuación"):verify_chain(modified)
    def test_reject_naive_timestamp(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"evidence";p.write_bytes(b"abc")
            record=register_evidence("E-1",p,"Analyst")
            with self.assertRaises(ValueError):
                append_event(record,"examined","Analyst","note","2026-11-10T12:00:00")
