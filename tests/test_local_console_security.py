"""Adversarial local-console API tests using synthetic evidence only."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from hexforge.server import main as server
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


@unittest.skipUnless(AVAILABLE, "FastAPI/test dependencies unavailable")
class LocalConsoleSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)
        self.host = {"host": "127.0.0.1:8765"}
        self.auth = {**self.host, "x-hexforge-token": server.SESSION_TOKEN}

    def test_host_prefix_attack_rejected(self):
        r = self.client.get("/api/health", headers={"host": "127.0.0.1:8765.evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_origin_prefix_attack_rejected(self):
        r = self.client.post("/api/server/stop", headers={**self.auth,
            "origin": "http://127.0.0.1:8765.evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_write_requires_token(self):
        r = self.client.post("/api/server/stop", headers=self.host)
        self.assertEqual(r.status_code, 403)

    def test_upload_and_redacted_report(self):
        r = self.client.post("/api/upload", files={"file": ("sample.bin", b"password=synthetic")},
                             headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        file_id = r.json()["file_id"]
        self.assertRegex(file_id, r"^[0-9a-f]{32}$")
        name = "synthetic-" + file_id + ".json"
        r = self.client.post("/api/report/write",
            json={"file_id": file_id, "report_mode": "redacted", "filename": name},
            headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.get("/api/report/download/" + name, headers=self.host)
        self.assertEqual(r.status_code, 200)
        report = r.json()
        self.assertNotIn("source_path", report)
        self.assertEqual(report["ascii_preview"], "")
        self.assertEqual(report["hex_preview"], "")

    def test_path_traversal_rejected(self):
        r = self.client.post("/api/report/write",
            json={"file_id": "a" * 32, "filename": "../bad.json"},
            headers=self.auth)
        self.assertEqual(r.status_code, 422)

    def test_file_id_traversal_rejected(self):
        r = self.client.post("/api/inspect",
            json={"file_id": "../../etc/passwd"}, headers=self.auth)
        self.assertEqual(r.status_code, 400)
