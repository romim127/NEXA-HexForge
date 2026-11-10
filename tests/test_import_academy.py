import unittest
from unittest.mock import patch
from hexforge.import_academy import explain_imports

class ImportAcademyTests(unittest.TestCase):
    @patch("hexforge.import_academy.inspect_imports")
    def test_known_api(self, mock):
        mock.return_value={"status":"parsed","imports":[{"dll":"kernel32.dll","functions":[{"name":"VirtualAlloc"},{"name":"CreateRemoteThread"}]}]}
        result=explain_imports("fixture.exe")
        self.assertEqual(result["function_count"],2)
        self.assertEqual(result["dlls"][0]["functions"][0]["category"],"memory")
        self.assertEqual(result["dlls"][0]["functions"][1]["called"],"unknown")
        self.assertFalse(result["execution_performed"])
    @patch("hexforge.import_academy.inspect_imports")
    def test_unknown_and_ordinal(self, mock):
        mock.return_value={"status":"parsed","imports":[{"dll":"demo.dll","functions":[{"name":"Mystery"},{"ordinal":17}]}]}
        result=explain_imports("fixture.exe")
        self.assertEqual(result["dlls"][0]["functions"][0]["category"],"unclassified")
        self.assertEqual(result["dlls"][0]["functions"][1]["category"],"ordinal")
    @patch("hexforge.import_academy.inspect_imports")
    def test_empty(self, mock):
        mock.return_value={"status":"no_import_directory","imports":[]}
        result=explain_imports("fixture.exe")
        self.assertEqual(result["dll_count"],0)
        self.assertEqual(result["verdict"],"not_determined")
