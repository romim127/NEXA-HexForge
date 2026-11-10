import tempfile
import unittest
from pathlib import Path
from math import isclose
from hexforge.entropy_academy import explain_entropy, inspect_section_entropy
from tests.test_hex_pe import synthetic_pe

class EntropyAcademyTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(explain_entropy(b"")["entropy_bits_per_byte"],0)
    def test_constant(self):
        self.assertEqual(explain_entropy(b"A"*100)["entropy_bits_per_byte"],0)
    def test_equal_distribution(self):
        r=explain_entropy(b"ABAB")
        self.assertTrue(isclose(r["entropy_bits_per_byte"],1))
        self.assertEqual(r["unique_values"],2)
    def test_all_bytes(self):
        self.assertEqual(explain_entropy(bytes(range(256)))["entropy_bits_per_byte"],8)
    def test_bounds(self):
        with self.assertRaises(ValueError):explain_entropy(b"X"*(1024*1024+1))
    def test_pe_section(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fixture.exe";p.write_bytes(synthetic_pe())
            result=inspect_section_entropy(p,0)
            self.assertEqual(result["section"],".text")
            self.assertEqual(result["sample_bytes"],32)
            self.assertTrue(result["permissions"]["executable"])
            self.assertFalse(result["execution_performed"])
    def test_bad_index(self):
        with self.assertRaises(ValueError):inspect_section_entropy("missing",-1)
