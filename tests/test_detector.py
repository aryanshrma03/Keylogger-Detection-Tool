import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from detector.engine import KeyloggerDetector
from detector.indicators import TelemetryItem


class KeyloggerDetectorTests(unittest.TestCase):

    def test_empty_detector(self):
        result = KeyloggerDetector().evaluate()
        self.assertEqual(result.score, 0)
        self.assertEqual(result.severity, "NORMAL")

    def test_normal_item(self):
        detector = KeyloggerDetector()
        result = detector.add_item(
            TelemetryItem(
                name="explorer.exe",
                path=r"C:\Windows\explorer.exe",
                signed=True,
            )
        )
        self.assertEqual(result.score, 0)
        self.assertEqual(result.suspicious_items, 0)

    def test_suspicious_correlated_item(self):
        detector = KeyloggerDetector()
        result = detector.add_item(
            TelemetryItem(
                name="keylogger.exe",
                path=r"C:\Users\User\AppData\Roaming\keylogger.exe",
                keyboard_hook=True,
                persistence=True,
                startup_entry=True,
                signed=False,
            )
        )
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.severity, "CRITICAL")

    def test_score_is_capped(self):
        detector = KeyloggerDetector()

        for i in range(10):
            result = detector.add_item(
                TelemetryItem(
                    name="keylogger.exe",
                    path=r"C:\Users\User\AppData\Roaming\keylogger.exe",
                    keyboard_hook=True,
                    persistence=True,
                    startup_entry=True,
                    signed=False,
                )
            )

        self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
