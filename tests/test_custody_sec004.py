"""Tests for chain of custody validation robustness (SEC-004)."""
import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from hexforge.custody import (
    register_evidence, append_event, verify_chain, verify_evidence,
    save_new, load_record, MAX_FILE, MAX_EVENTS
)


class TestChainOfCustodyValidation(unittest.TestCase):
    """SEC-004: Chain of custody robustness with hash chain validation."""

    def setUp(self):
        """Create temporary directory."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Create test evidence file
        self.evidence_file = self.tmppath / "evidence.bin"
        self.evidence_file.write_bytes(b"Test evidence data")

    def tearDown(self):
        """Clean up."""
        self.tmpdir.cleanup()

    def test_register_evidence_creates_valid_chain(self):
        """SEC-004-1: register_evidence creates valid chain structure."""
        record = register_evidence(
            "EVD-001",
            self.evidence_file,
            "Detective Smith"
        )

        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["evidence_id"], "EVD-001")
        self.assertEqual(len(record["events"]), 1)
        self.assertEqual(record["events"][0]["action"], "acquired")

    def test_append_event_extends_chain(self):
        """SEC-004-2: append_event properly extends the hash chain."""
        record = register_evidence("EVD-002", self.evidence_file, "Smith")

        record = append_event(record, "examined", "Jones", "Visual inspection performed")

        self.assertEqual(len(record["events"]), 2)
        self.assertEqual(record["events"][1]["sequence"], 2)
        self.assertIsNotNone(record["events"][1]["previous_hash"])
        self.assertEqual(record["events"][1]["previous_hash"], record["events"][0]["entry_hash"])

    def test_verify_chain_detects_tampering(self):
        """SEC-004-3: verify_chain detects modification of events."""
        record = register_evidence("EVD-003", self.evidence_file, "Smith")
        record = append_event(record, "examined", "Jones", "Inspection")

        # Tamper with an event
        record["events"][0]["note"] = "Modified note"

        with self.assertRaises(ValueError) as ctx:
            verify_chain(record)
        self.assertIn("Hash", str(ctx.exception))

    def test_verify_chain_detects_sequence_violation(self):
        """SEC-004-4: verify_chain detects sequence number violations."""
        record = register_evidence("EVD-004", self.evidence_file, "Smith")
        record = append_event(record, "examined", "Jones", "Inspection")

        # Break sequence
        record["events"][1]["sequence"] = 99

        with self.assertRaises(ValueError) as ctx:
            verify_chain(record)
        self.assertIn("Secuencia", str(ctx.exception))

    def test_verify_chain_detects_hash_break(self):
        """SEC-004-5: verify_chain detects broken previous_hash."""
        record = register_evidence("EVD-005", self.evidence_file, "Smith")
        record = append_event(record, "examined", "Jones", "Inspection")

        # Break hash chain
        record["events"][1]["previous_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"

        with self.assertRaises(ValueError) as ctx:
            verify_chain(record)
        self.assertIn("Secuencia", str(ctx.exception))

    def test_invalid_schema_version(self):
        """SEC-004-6: verify_chain rejects invalid schema version."""
        record = {
            "schema_version": 2,  # Invalid
            "evidence_id": "EVD-006",
            "events": []
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_evidence_id(self):
        """SEC-004-7: verify_chain rejects invalid evidence_id."""
        record = {
            "schema_version": 1,
            "evidence_id": "",  # Empty
            "events": []
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_evidence_hash(self):
        """SEC-004-8: verify_chain rejects malformed evidence hash."""
        record = {
            "schema_version": 1,
            "evidence_id": "EVD-008",
            "sha256": "not_a_valid_hash",  # Invalid
            "events": []
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_evidence_hash_too_short(self):
        """SEC-004-9: verify_chain rejects short evidence hash."""
        record = {
            "schema_version": 1,
            "evidence_id": "EVD-009",
            "sha256": "abc123",  # Too short
            "events": []
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_evidence_hash_non_hex(self):
        """SEC-004-10: verify_chain rejects non-hex evidence hash."""
        record = {
            "schema_version": 1,
            "evidence_id": "EVD-010",
            "sha256": "g" * 64,  # Invalid hex character
            "events": []
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_events_not_list(self):
        """SEC-004-11: verify_chain requires events to be a list."""
        record = {
            "schema_version": 1,
            "evidence_id": "EVD-011",
            "sha256": "a" * 64,
            "events": "not a list"
        }

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_too_many_events(self):
        """SEC-004-12: verify_chain rejects too many events."""
        record = register_evidence("EVD-012", self.evidence_file, "Smith")

        # Add a few events to get close to limit
        for i in range(5):
            record = append_event(record, "examined", f"Jones{i}", f"Inspection {i}")

        # Manually craft a record with MAX_EVENTS + 1 events to avoid slow test
        record["events"].extend([{
            "sequence": i + len(record["events"]),
            "action": "verified",
            "actor": "Test",
            "note": "Test event",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "previous_hash": record["events"][-1]["entry_hash"],
            "entry_hash": "a" * 64
        } for i in range(MAX_EVENTS)])

        with self.assertRaises(ValueError):
            verify_chain(record)

    def test_invalid_action(self):
        """SEC-004-13: append_event rejects invalid action."""
        record = register_evidence("EVD-013", self.evidence_file, "Smith")

        with self.assertRaises(ValueError):
            append_event(record, "invalid_action", "Jones", "Note")

    def test_invalid_actor(self):
        """SEC-004-14: append_event rejects invalid actor."""
        record = register_evidence("EVD-014", self.evidence_file, "Smith")

        with self.assertRaises(ValueError):
            append_event(record, "examined", "", "Note")  # Empty actor

    def test_invalid_actor_too_long(self):
        """SEC-004-15: append_event rejects oversized actor."""
        record = register_evidence("EVD-015", self.evidence_file, "Smith")

        with self.assertRaises(ValueError):
            append_event(record, "examined", "X" * 200, "Note")  # Too long

    def test_invalid_note_too_long(self):
        """SEC-004-16: append_event rejects oversized note."""
        record = register_evidence("EVD-016", self.evidence_file, "Smith")

        with self.assertRaises(ValueError):
            append_event(record, "examined", "Jones", "X" * 3000)  # Exceeds 2048

    def test_invalid_timestamp_format(self):
        """SEC-004-17: append_event rejects invalid timestamp format."""
        record = register_evidence("EVD-017", self.evidence_file, "Smith")

        with self.assertRaises(ValueError):
            append_event(record, "examined", "Jones", "Note", "invalid-timestamp")

    def test_non_utc_timestamp_rejected(self):
        """SEC-004-18: append_event rejects non-UTC timestamps."""
        record = register_evidence("EVD-018", self.evidence_file, "Smith")

        # Timestamp with offset instead of Z
        bad_timestamp = "2024-01-01T12:00:00+01:00"

        with self.assertRaises(ValueError) as ctx:
            append_event(record, "examined", "Jones", "Note", bad_timestamp)
        self.assertIn("UTC", str(ctx.exception))

    def test_naive_timestamp_rejected(self):
        """SEC-004-19: append_event rejects naive (non-TZ) timestamps."""
        record = register_evidence("EVD-019", self.evidence_file, "Smith")

        # Naive timestamp
        bad_timestamp = "2024-01-01T12:00:00"

        with self.assertRaises(ValueError) as ctx:
            append_event(record, "examined", "Jones", "Note", bad_timestamp)
        self.assertIn("UTC", str(ctx.exception))

    def test_verify_evidence_hash_match(self):
        """SEC-004-20: verify_evidence confirms hash match with file."""
        record = register_evidence("EVD-020", self.evidence_file, "Smith")

        result = verify_evidence(record, self.evidence_file)

        self.assertTrue(result["evidence_hash_matches"])
        self.assertTrue(result["size_matches"])

    def test_verify_evidence_hash_mismatch(self):
        """SEC-004-21: verify_evidence detects hash mismatch."""
        record = register_evidence("EVD-021", self.evidence_file, "Smith")

        # Modify file
        self.evidence_file.write_bytes(b"Modified content")

        result = verify_evidence(record, self.evidence_file)

        self.assertFalse(result["evidence_hash_matches"])

    def test_verify_evidence_size_mismatch(self):
        """SEC-004-22: verify_evidence detects size mismatch."""
        record = register_evidence("EVD-022", self.evidence_file, "Smith")

        # Modify file
        self.evidence_file.write_bytes(b"Modified content")

        result = verify_evidence(record, self.evidence_file)

        self.assertFalse(result["size_matches"])

    def test_save_new_creates_file(self):
        """SEC-004-23: save_new creates custody record file."""
        record = register_evidence("EVD-023", self.evidence_file, "Smith")

        output_file = self.tmppath / "custody_record.json"
        save_new(record, output_file)

        self.assertTrue(output_file.exists())

    def test_save_new_prevents_overwrite(self):
        """SEC-004-24: save_new fails if file exists (atomic write)."""
        record = register_evidence("EVD-024", self.evidence_file, "Smith")

        output_file = self.tmppath / "custody_record.json"
        save_new(record, output_file)

        # Try to save again to same path
        with self.assertRaises(FileExistsError):
            save_new(record, output_file)

    def test_load_record_reads_valid_file(self):
        """SEC-004-25: load_record reads valid custody file."""
        record = register_evidence("EVD-025", self.evidence_file, "Smith")

        output_file = self.tmppath / "custody_record.json"
        save_new(record, output_file)

        loaded = load_record(output_file)

        self.assertEqual(loaded["evidence_id"], "EVD-025")
        self.assertEqual(len(loaded["events"]), 1)

    def test_load_record_rejects_symlink(self):
        """SEC-004-26: load_record rejects symlink to custody file."""
        record = register_evidence("EVD-026", self.evidence_file, "Smith")

        actual_file = self.tmppath / "custody_actual.json"
        save_new(record, actual_file)

        link_file = self.tmppath / "custody_link.json"
        try:
            link_file.symlink_to(actual_file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this platform")

        with self.assertRaises(ValueError):
            load_record(link_file)

    def test_load_record_rejects_oversized_file(self):
        """SEC-004-27: load_record rejects file exceeding MAX_FILE."""
        record = register_evidence("EVD-027", self.evidence_file, "Smith")

        output_file = self.tmppath / "custody_large.json"
        # Create file larger than MAX_FILE
        output_file.write_bytes(b"X" * (MAX_FILE + 1))

        with self.assertRaises(ValueError):
            load_record(output_file)

    def test_all_valid_actions_work(self):
        """SEC-004-28: All valid custody actions are accepted."""
        record = register_evidence("EVD-028", self.evidence_file, "Smith")

        actions = ["acquired", "transferred", "examined", "stored", "verified", "released"]
        for action in actions[1:]:  # Skip 'acquired' as it's already in record
            record = append_event(record, action, "Jones", f"Action: {action}")

        self.assertEqual(len(record["events"]), len(actions))

    def test_evidence_id_normalization(self):
        """SEC-004-29: evidence_id whitespace is stripped."""
        record = register_evidence(
            "  EVD-029  ",
            self.evidence_file,
            "Smith"
        )

        self.assertEqual(record["evidence_id"], "EVD-029")

    def test_actor_whitespace_normalized(self):
        """SEC-004-30: actor whitespace is stripped."""
        record = register_evidence("EVD-030", self.evidence_file, "Smith")

        record = append_event(record, "examined", "  Jones  ", "Note")

        self.assertEqual(record["events"][1]["actor"], "Jones")

    def test_timestamp_z_format_normalized(self):
        """SEC-004-31: Timestamp Z format is preserved."""
        record = register_evidence("EVD-031", self.evidence_file, "Smith")

        z_timestamp = "2024-01-01T12:00:00Z"
        record = append_event(record, "examined", "Jones", "Note", z_timestamp)

        self.assertTrue(record["events"][1]["timestamp_utc"].endswith("Z"))

    def test_multiple_events_chain_integrity(self):
        """SEC-004-32: Chain integrity maintained across multiple events."""
        record = register_evidence("EVD-032", self.evidence_file, "Smith")

        for i in range(5):
            record = append_event(
                record,
                "examined" if i % 2 == 0 else "verified",
                f"Actor{i}",
                f"Note {i}"
            )

        # Verify entire chain is valid
        result = verify_chain(record)
        self.assertTrue(result["chain_valid"])
        self.assertEqual(result["events"], 6)  # 1 acquired + 5 appended


if __name__ == "__main__":
    unittest.main()
