
import io
import unittest
from login_investigator import investigate


class InvestigatorTests(unittest.TestCase):

    def test_repeated_failures_then_success(self):
        csv_text = """timestamp,username,ip,status
2026-10-22 09:00:00,alex,203.0.113.10,FAIL
2026-10-22 09:02:00,alex,203.0.113.10,FAIL
2026-10-22 09:03:00,alex,203.0.113.10,SUCCESS
"""
        alerts = investigate(io.StringIO(csv_text))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk"], 4)

    def test_outside_hours_adds_one_point(self):
        csv_text = """timestamp,username,ip,status
2026-10-22 23:15:00,sam,198.51.100.20,SUCCESS
"""
        alerts = investigate(io.StringIO(csv_text))
        self.assertEqual(alerts, [])

    def test_single_failure_then_success_below_threshold(self):
        csv_text = """timestamp,username,ip,status
2026-10-22 14:00:00,mira,192.0.2.30,FAIL
2026-10-22 14:01:00,mira,192.0.2.30,SUCCESS
"""
        alerts = investigate(io.StringIO(csv_text))
        self.assertEqual(alerts, [])

    def test_out_of_order_events(self):
        csv_text = """timestamp,username,ip,status
2026-10-22 09:03:00,alex,203.0.113.10,SUCCESS
2026-10-22 09:00:00,alex,203.0.113.10,FAIL
2026-10-22 09:02:00,alex,203.0.113.10,FAIL
"""
        alerts = investigate(io.StringIO(csv_text))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk"], 4)


if __name__ == "__main__":
    unittest.main()
