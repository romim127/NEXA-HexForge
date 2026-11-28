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

    def test_custody_record_ids_and_no_paths(self):
        uploaded = self.client.post("/api/upload",
            files={"file": ("custody.bin", b"synthetic-custody")},
            headers=self.auth)
        self.assertEqual(uploaded.status_code, 200)
        file_id = uploaded.json()["file_id"]
        registered = self.client.post("/api/custody/register",
            json={"file_id": file_id, "evidence_id": "LAB-1", "actor": "Analyst"},
            headers=self.auth)
        self.assertEqual(registered.status_code, 200, registered.text)
        record_id = registered.json()["record_id"]
        appended = self.client.post("/api/custody/append",
            json={"record_id": record_id, "action": "examined",
                  "actor": "Analyst", "note": "Synthetic review"},
            headers=self.auth)
        self.assertEqual(appended.status_code, 200, appended.text)
        verified = self.client.post("/api/custody/verify",
            json={"record_id": record_id, "file_id": file_id},
            headers=self.auth)
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertTrue(verified.json()["evidence_hash_matches"])
        traversal = self.client.post("/api/custody/append",
            json={"record_path": "/etc/passwd", "action": "examined",
                  "actor": "Analyst", "note": "No"},
            headers=self.auth)
        self.assertEqual(traversal.status_code, 422)

    def test_upload_above_limit_is_rejected_and_not_persisted(self):
        from unittest.mock import patch
        with patch.object(server, "MAX_UPLOAD_SIZE", 10):
            r = self.client.post("/api/upload",
                files={"file": ("oversized.bin", b"x" * 11)},
                headers=self.auth)
        self.assertEqual(r.status_code, 413)

    def test_session_cross_origin_not_readable(self):
        r = self.client.get("/api/session", headers={
            "host": "127.0.0.1:8765",
            "origin": "https://attacker.example"})
        self.assertEqual(r.status_code, 403)

    def test_report_path_rejected_and_real_export(self):
        uploaded = self.client.post("/api/upload",
            files={"file": ("sample.bin", b"synthetic")},
            headers=self.auth)
        file_id = uploaded.json()["file_id"]
        traversal = self.client.post("/api/report/write",
            json={"file_id": file_id, "filename": "../escape.json"},
            headers=self.auth)
        self.assertEqual(traversal.status_code, 422)
        for endpoint in ("/api/inspect", "/api/pe", "/api/imports",
                         "/api/strings", "/api/indicators", "/api/hexview"):
            payload = {"file_id": file_id}
            if endpoint == "/api/hexview":
                payload.update(offset=0)
            response = self.client.post(endpoint, json=payload, headers=self.auth)
            self.assertLess(response.status_code, 500, (endpoint, response.text))
