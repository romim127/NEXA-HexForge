import unittest
from hexforge.timeline import correlate

HASH = "a"*64
def ev(source, id, when, path="C:/Tools/example.exe", digest=None):
    return {"source":source,"artifact_id":id,"file_path":path,
            "observed_time_utc":when,"sha256":digest,
            "raw_row_number": 2 if source == "prefetch" else 3}

def doc(events):
    return {"schema_version":1,"source_sha256":"b"*64,"records":events}

class TimelineTests(unittest.TestCase):
    def test_cross_source_hash_correlation(self):
        r=correlate(doc([ev("amcache","A","2026-11-10T12:01:00Z",digest=HASH),
                         ev("prefetch","P","2026-11-10T12:00:00Z",digest=HASH)]))
        self.assertEqual(r["correlation_count"],1)
        self.assertEqual(r["correlations"][0]["match_basis"],"sha256")
        self.assertEqual(r["correlations"][0]["confidence"],"moderate")
        self.assertFalse(r["execution_confirmed"])
    def test_no_cross_source_different_files(self):
        r=correlate(doc([ev("prefetch","P","2026-11-10T12:00:00Z"),
                         ev("amcache","A","2026-11-10T12:00:10Z",path="D:/other.exe")]))
        self.assertEqual(r["correlation_count"],0)
    def test_outside_window(self):
        r=correlate(doc([ev("prefetch","P","2026-11-10T12:00:00Z"),
                         ev("amcache","A","2026-11-10T12:30:00Z")]),60)
        self.assertEqual(r["correlation_count"],0)
    def test_path_match_low_confidence(self):
        r=correlate(doc([ev("prefetch","P","2026-11-10T12:00:00Z"),
                         ev("amcache","A","2026-11-10T12:00:01Z")]))
        self.assertEqual(r["correlations"][0]["confidence"],"low")
    def test_same_source_not_correlated(self):
        r=correlate(doc([ev("prefetch","P1","2026-11-10T12:00:00Z"),
                         ev("prefetch","P2","2026-11-10T12:00:01Z")]))
        self.assertEqual(r["correlation_count"],0)
    def test_invalid_window(self):
        with self.assertRaises(ValueError):correlate(doc([]),86401)
    def test_invalid_time(self):
        with self.assertRaises(ValueError):correlate(doc([ev("prefetch","P","2026-11-10T12:00:00")]))
