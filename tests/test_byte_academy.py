import tempfile
import unittest
from pathlib import Path
from hexforge.byte_academy import explain_byte, inspect_byte

class ByteAcademyTests(unittest.TestCase):
    def test_mz(self):
        result=explain_byte(0x4D,0)
        self.assertEqual(result["hex"],"4D")
        self.assertEqual(result["binary"],"01001101")
        self.assertEqual(result["decimal"],77)
        self.assertEqual(result["ascii"],"M")
        self.assertEqual(sum(x["contribution"] for x in result["steps"]),77)
    def test_ff(self):
        self.assertEqual(explain_byte(255)["binary"],"11111111")
        self.assertFalse(explain_byte(255)["printable_ascii"])
    def test_file_offset(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fixture.bin";p.write_bytes(b"MZ"+bytes((0,255)))
            self.assertEqual(inspect_byte(p,1)["ascii"],"Z")
            self.assertEqual(inspect_byte(p,3)["hex"],"FF")
            with self.assertRaises(ValueError):inspect_byte(p,4)
    def test_bad_inputs(self):
        for value in (-1,256,1.2,True):
            with self.subTest(value=value), self.assertRaises(ValueError):explain_byte(value)
        with self.assertRaises(ValueError):explain_byte(12,-1)
