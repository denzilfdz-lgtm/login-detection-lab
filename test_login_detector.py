
import unittest
from login_detector_v2 import detect_alerts


class LoginDetectorTests(unittest.TestCase):

    def test_detects_three_failures(self):
        logs = [
            "2026-10-22 10:00:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:00:30,alex,203.0.113.10,FAIL",
            "2026-10-22 10:01:00,alex,203.0.113.10,FAIL",
        ]

        alerts = detect_alerts(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 3)

    def test_handles_out_of_order_records(self):
        logs = [
            "2026-10-22 10:01:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:00:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:00:30,alex,203.0.113.10,FAIL",
        ]

        alerts = detect_alerts(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["start"].strftime("%H:%M:%S"),
            "10:00:00",
        )

    def test_ignores_successful_logins(self):
        logs = [
            "2026-10-22 10:00:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:00:20,alex,203.0.113.10,SUCCESS",
            "2026-10-22 10:00:40,alex,203.0.113.10,FAIL",
        ]

        self.assertEqual(detect_alerts(logs), [])

    def test_ignores_failures_outside_window(self):
        logs = [
            "2026-10-22 10:00:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:01:00,alex,203.0.113.10,FAIL",
            "2026-10-22 10:02:01,alex,203.0.113.10,FAIL",
        ]

        self.assertEqual(detect_alerts(logs), [])

    def test_emits_only_one_alert_per_ip(self):
        logs = [
            f"2026-10-22 10:00:{second:02d},alex,"
            "203.0.113.10,FAIL"
            for second in (0, 10, 20, 30, 40)
        ]

        alerts = detect_alerts(logs)
        self.assertEqual(len(alerts), 1)

    def test_skips_malformed_records(self):
        logs = [
            "this is not a valid record",
            "2026-10-22 10:00:00,alex,203.0.113.10,FAIL",
        ]

        self.assertEqual(detect_alerts(logs), [])


if __name__ == "__main__":
    unittest.main()
